#!/usr/bin/env python3
"""
ra89r.py -- exact .icf codec for Retevis RA89R / TYT UV8800 / TH9000D firmware.

    icf_to_bin(icf_path, bin_path)      .icf  ->  flat firmware image
    bin_to_icf(bin_path, icf_path)      image ->  .icf the radio accepts

No calibration, no probing, no guessing. The check byte is computed.

-----------------------------------------------------------------------------
THE FORMAT
-----------------------------------------------------------------------------

An .icf is ASCII hex, one record per CR-separated line. Each record is

    [6-byte header][payload][1 check byte]

Every byte of the header is XOR'd with a family baseline; everything after it
is XOR'd with a per-record key derived from the header:

    h[i]   = header_raw[i] ^ BASELINE                       i = 0..5
    length = (h[0] << 8) | h[1]                             payload size
    addr   = ((h[2] << 16) | (h[3] << 8) | h[4]) * 0x100    destination in flash
    key    = h[0]^h[1]^h[2]^h[3]^h[4]^h[5] ^ BASELINE

    payload[j] = payload_raw[j] ^ key
    check      = check_raw ^ key                            <-- encrypted too

and the record is valid exactly when

    ( sum(h[0..5]) + sum(payload) + check )  mod 256  ==  0

so the byte to store is

    check_raw = key ^ ( -(sum(h) + sum(payload)) mod 256 )

BASELINE is per radio family: 0x66 RA89R, 0x88 UV8800, 0x90 TH9000D. It is
detected automatically by trying all 256 values and keeping the one under which
every record validates.

Verified against 616 records across nine stock firmware files from three
different radios — every record, zero exceptions — and against four patched
records whose check bytes were previously found by brute force on hardware
(0x6D, 0xC3, 0xC3, 0xE1); the formula reproduces all four.

Source: the validator at 0x08000BE0 in the RA89R bootloader, read out of the
radio over the serial port. It sums length+7 bytes starting at the header and
requires the total to be zero:

    bl   0x08000C88          ; length = (h[0]<<8) | h[1]
    bl   0x080009FC          ; decrypt header, payload AND check byte
    ...  r6 = (r6 + buf[i+5]) & 0xFF   for i in 0 .. length+6
    cbnz r6, reject

-----------------------------------------------------------------------------
WHY THE OLD TOOL NEEDED PROBING
-----------------------------------------------------------------------------

The trailing byte is XOR'd with the per-record key like everything else. Read
as plaintext it looks like a lookup-table hash over the payload, because the
key aliases the sum differently in every record. That one missing XOR is the
whole story.

-----------------------------------------------------------------------------
USAGE
-----------------------------------------------------------------------------

    python ra89r.py decode firmware.icf firmware.bin
    # edit firmware.bin in place -- the size must not change
    python ra89r.py encode firmware.bin patched.icf

    python ra89r.py verify  firmware.icf      # check every record
    python ra89r.py info    firmware.icf      # record table

decode writes a sidecar <bin>.meta holding each record's header, so encode can
rebuild the file byte-for-byte. Without the sidecar, encode still works if you
pass --like <original.icf> to copy its record layout.
"""

import argparse
import os
import struct
import sys

SEP = "\r"
MAGIC = b"RA89RMETA3"
KNOWN_BASELINES = (0x66, 0x88, 0x90)


class IcfError(Exception):
    pass


# --------------------------------------------------------------------------
# record primitives
# --------------------------------------------------------------------------

class Record(object):
    __slots__ = ("header", "payload", "baseline")

    def __init__(self, header, payload, baseline):
        self.header = bytes(header)          # 6 bytes, decrypted
        self.payload = bytes(payload)        # decrypted
        self.baseline = baseline

    @property
    def length(self):
        return (self.header[0] << 8) | self.header[1]

    @property
    def address(self):
        return ((self.header[2] << 16) | (self.header[3] << 8) | self.header[4]) * 0x100

    @property
    def key(self):
        k = self.baseline
        for b in self.header:
            k ^= b
        return k

    @property
    def check(self):
        """The plaintext check byte: whatever makes the record sum to zero."""
        return (-(sum(self.header) + sum(self.payload))) & 0xFF

    def encode(self):
        k = self.key
        b = bytearray(x ^ self.baseline for x in self.header)
        b += bytes(x ^ k for x in self.payload)
        b.append(self.check ^ k)
        return bytes(b)


def parse_record(raw, baseline):
    if len(raw) < 8:
        raise IcfError("record is only %d bytes" % len(raw))
    header = bytes(x ^ baseline for x in raw[:6])
    length = (header[0] << 8) | header[1]
    if len(raw) != 6 + length + 1:
        raise IcfError("header says %d payload bytes but the record holds %d"
                       % (length, len(raw) - 7))
    key = baseline
    for b in header:
        key ^= b
    payload = bytes(x ^ key for x in raw[6:6 + length])
    stored = raw[6 + length] ^ key
    rec = Record(header, payload, baseline)
    return rec, stored


def read_raw_records(path):
    with open(path, "r", newline="") as f:
        text = f.read()
    parts = text.split(SEP)
    if len(parts) < 2:
        parts = text.split("\n")
    out = []
    for line in parts:
        line = line.strip().lstrip("n")
        if len(line) < 2:
            continue
        try:
            out.append(bytes.fromhex(line))
        except ValueError:
            raise IcfError("line %d is not hex" % (len(out) + 1))
    if not out:
        raise IcfError("no records found -- is this an .icf file?")
    return out


def detect_baseline(raws):
    """Return the baseline under which every record validates, else raise."""
    ordered = list(KNOWN_BASELINES) + [b for b in range(256) if b not in KNOWN_BASELINES]
    for bl in ordered:
        try:
            for raw in raws:
                rec, stored = parse_record(raw, bl)
                if stored != rec.check:
                    break
            else:
                return bl
        except IcfError:
            continue
    raise IcfError("no baseline validates this file -- it is corrupt, or a "
                   "family this tool has not seen")


# --------------------------------------------------------------------------
# the two functions
# --------------------------------------------------------------------------

def icf_to_bin(icf_path, bin_path, meta_path=None):
    """Decode an .icf into a flat image. Returns (image, records, baseline)."""
    raws = read_raw_records(icf_path)
    baseline = detect_baseline(raws)
    recs = [parse_record(r, baseline)[0] for r in raws]

    ordered = sorted(recs, key=lambda r: r.address)
    base = ordered[0].address
    size = ordered[-1].address + ordered[-1].length - base
    image = bytearray(b"\xFF" * size)
    for r in ordered:
        off = r.address - base
        image[off:off + r.length] = r.payload

    with open(bin_path, "wb") as f:
        f.write(image)

    if meta_path is None:
        meta_path = bin_path + ".meta"
    with open(meta_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<BIII", baseline, base, size, len(recs)))
        for r in recs:                       # file order, not address order
            f.write(r.header)
    return bytes(image), recs, baseline


def bin_to_icf(bin_path, icf_path, meta_path=None, like=None):
    """Re-encode a (possibly edited) image into a valid .icf."""
    with open(bin_path, "rb") as f:
        image = f.read()

    if like:
        raws = read_raw_records(like)
        baseline = detect_baseline(raws)
        headers = [bytes(x ^ baseline for x in r[:6]) for r in raws]
        addrs = [((h[2] << 16) | (h[3] << 8) | h[4]) * 0x100 for h in headers]
        base = min(addrs)
        size = max(a + ((h[0] << 8) | h[1]) for a, h in zip(addrs, headers)) - base
    else:
        if meta_path is None:
            meta_path = bin_path + ".meta"
        if not os.path.exists(meta_path):
            raise IcfError("no sidecar at %s -- decode the original first, or "
                           "pass --like <original.icf>" % meta_path)
        with open(meta_path, "rb") as f:
            blob = f.read()
        if not blob.startswith(MAGIC):
            raise IcfError("%s is not a sidecar written by this version" % meta_path)
        off = len(MAGIC)
        baseline, base, size, n = struct.unpack_from("<BIII", blob, off)
        off += struct.calcsize("<BIII")
        headers = [blob[off + i * 6: off + i * 6 + 6] for i in range(n)]

    if len(image) != size:
        raise IcfError("image is %d bytes but this firmware is %d -- editing "
                       "must not change the size" % (len(image), size))

    lines = []
    for h in headers:
        length = (h[0] << 8) | h[1]
        addr = ((h[2] << 16) | (h[3] << 8) | h[4]) * 0x100
        off = addr - base
        rec = Record(h, image[off:off + length], baseline)
        lines.append(rec.encode().hex().upper())

    with open(icf_path, "w", newline="") as f:
        f.write(SEP.join(lines) + SEP)
    return len(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_decode(a):
    image, recs, bl = icf_to_bin(a.icf, a.bin, a.meta)
    print("baseline 0x%02X, %d records, %d bytes -> %s"
          % (bl, len(recs), len(image), a.bin))
    print("flash %08X..%08X" % (min(r.address for r in recs),
                                max(r.address + r.length for r in recs)))
    print("sidecar: %s" % (a.meta or (a.bin + ".meta")))
    return 0


def cmd_encode(a):
    n = bin_to_icf(a.bin, a.icf, a.meta, a.like)
    print("%d records -> %s" % (n, a.icf))
    bad = [i for i, (r, s) in enumerate(
        (parse_record(x, detect_baseline(read_raw_records(a.icf)))
         for x in read_raw_records(a.icf))) if s != r.check]
    print("self-check: %s" % ("all records valid" if not bad else "FAILED at %s" % bad))
    return 0 if not bad else 1


def cmd_verify(a):
    raws = read_raw_records(a.icf)
    try:
        bl = detect_baseline(raws)
    except IcfError as e:
        print("FAIL: %s" % e)
        # report which records disagree under the most likely baseline
        for guess in KNOWN_BASELINES:
            try:
                bad = [i for i, raw in enumerate(raws)
                       if parse_record(raw, guess)[1] != parse_record(raw, guess)[0].check]
            except IcfError:
                continue
            if len(bad) < len(raws):
                print("  under baseline 0x%02X, %d of %d records fail: %s"
                      % (guess, len(bad), len(raws), bad[:16]))
        return 1
    print("baseline 0x%02X -- all %d records valid" % (bl, len(raws)))
    return 0


def cmd_info(a):
    raws = read_raw_records(a.icf)
    bl = detect_baseline(raws)
    print("baseline 0x%02X, %d records\n" % (bl, len(raws)))
    print("  #   address     len   key  check")
    for i, raw in enumerate(raws):
        r, stored = parse_record(raw, bl)
        print("  %-3d %08X  %5d  %02X   %02X%s"
              % (i, r.address, r.length, r.key, raw[-1],
                 "" if stored == r.check else "   <-- INVALID"))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("---")[0].strip(),
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("decode", help=".icf -> .bin")
    d.add_argument("icf"); d.add_argument("bin"); d.add_argument("--meta")
    d.set_defaults(fn=cmd_decode)

    e = sub.add_parser("encode", help=".bin -> .icf")
    e.add_argument("bin"); e.add_argument("icf")
    e.add_argument("--meta"); e.add_argument("--like",
                   help="copy the record layout from this .icf instead of a sidecar")
    e.set_defaults(fn=cmd_encode)

    v = sub.add_parser("verify", help="validate every check byte")
    v.add_argument("icf"); v.set_defaults(fn=cmd_verify)

    i = sub.add_parser("info", help="list the records")
    i.add_argument("icf"); i.set_defaults(fn=cmd_info)

    a = p.parse_args(argv)
    if not getattr(a, "fn", None):
        p.print_help()
        return 2
    try:
        return a.fn(a)
    except IcfError as ex:
        print("error: %s" % ex, file=sys.stderr)
        return 1
    except FileNotFoundError as ex:
        print("error: %s" % ex, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
