# Retevis RA89R ICF to binary converter

Vibe coded script that converts a .icf firmware from a Retevis RA89R to a binary that you can modify with ghidra and then allows you to convert it back to a .icf

The bootloader of the Retevis has a validator so I attached the bootloader.bin file if you want to inspect it. 
To extract the bootloader a custom firmware was made that dumped that part of the code.

To read a binary with ghidra you need to put:

Processor: ARM
Variant: Cortex
Size: 32
Endian: little
Compiler: default
Base Address: 0x08000000

Retevis MCU: Puya PY32F403
