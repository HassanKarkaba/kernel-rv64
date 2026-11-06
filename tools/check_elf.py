#!/usr/bin/env python3
"""Independently reject dynamic, writable-executable, or unresolved RV64 kernel ELF."""
import argparse
from pathlib import Path
import struct
import sys


def scan_integer_code(code, virtual_address):
    """Walk instruction boundaries in the selected RV64IMAC executable bytes.

    The profile permits 16- and 32-bit encodings only. This is a rejection
    scanner for floating/vector opcodes, not a proof that every opcode is legal.
    Zero alignment padding is the intentional illegal/unimplemented instruction.
    """
    position = 0
    count = 0
    while position < len(code):
        if len(code) - position < 2:
            raise ValueError("truncated executable instruction")
        halfword = int.from_bytes(code[position:position + 2], "little")
        quadrant = halfword & 3
        if quadrant != 3:
            if quadrant in (0, 2) and halfword >> 13 in (1, 5):
                raise ValueError(f"compressed floating-point instruction at {virtual_address + position:#x}")
            position += 2
        else:
            if halfword & 0x1F == 0x1F:
                raise ValueError("instruction encodings longer than 32 bits are unsupported")
            if len(code) - position < 4:
                raise ValueError("truncated 32-bit executable instruction")
            opcode = halfword & 0x7F
            if opcode in (0x07, 0x27, 0x43, 0x47, 0x4B, 0x4F, 0x53, 0x57):
                raise ValueError(f"floating-point or vector instruction at {virtual_address + position:#x}")
            position += 4
        count += 1
    return count


def check(path, kernel=False):
    data = Path(path).read_bytes()
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("not ELF64 little endian version 1")
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if (kind, machine, version, ehsize, phsize) != (2, 243, 1, 64, 56):
        raise ValueError("ELF type, architecture, version or header size mismatch")
    if flags & ~1:
        raise ValueError("ELF uses unsupported ABI flags")
    if kernel and entry != 0x80200000:
        raise ValueError("kernel entry must be 0x80200000")
    def region(start, size):
        if start > len(data) or size > len(data) - start:
            raise ValueError("ELF range is outside the file")
        return data[start:start + size]
    region(phoff, phsize * phnum)
    loads = []
    instructions = 0
    for i in range(phnum):
        typ, perm, off, va, pa, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, phoff + phsize * i)
        if typ in (2, 3):
            raise ValueError("dynamic loading is forbidden")
        if typ != 1:
            continue
        if filesz > memsz or perm & ~7 or perm & 3 == 3 or not perm & 4:
            raise ValueError("invalid LOAD sizes or permissions")
        segment = region(off, filesz)
        if perm & 1:
            instructions += scan_integer_code(segment, va)
        if memsz:
            loads.append((va, va + memsz, perm))
    if not any(lo <= entry < hi and perm & 1 for lo, hi, perm in loads):
        raise ValueError("entry is not in an executable LOAD segment")
    for i, (lo, hi, _) in enumerate(loads):
        if any(lo < otherhi and otherlo < hi for otherlo, otherhi, _ in loads[:i]):
            raise ValueError("overlapping LOAD segments")
    if shnum:
        if shsize != 64:
            raise ValueError("unsupported section header size")
        region(shoff, shsize * shnum)
        for i in range(shnum):
            section = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize)
            _, typ, _, _, off, size, link, _, _, entsize = section
            if typ not in (2, 11):
                continue
            if typ == 11:
                raise ValueError("dynamic symbols are forbidden")
            if entsize != 24 or size % entsize or link >= shnum:
                raise ValueError("invalid symbol table")
            symbols = region(off, size)
            for pos in range(0, size, entsize):
                name, info, other, section_index, value, symbol_size = struct.unpack_from("<IBBHQQ", symbols, pos)
                if section_index == 0 and any((name, info, other, value, symbol_size)):
                    raise ValueError("unresolved symbol")
    return {"entry": hex(entry), "load_segments": len(loads), "instructions_scanned": instructions, "status": "PASS"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel", action="store_true")
    p.add_argument("elf")
    args = p.parse_args()
    try:
        print(check(args.elf, args.kernel))
    except (OSError, ValueError, struct.error) as error:
        p.exit(2, f"ELF check: {error}\n")


if __name__ == "__main__":
    main()
