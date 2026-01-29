#!/usr/bin/env python3
"""
Patch ELF program headers that live in the lower half so Limine accepts them.
Only touches non-PT_LOAD headers and keeps loadable segments intact.
"""

import struct
import sys

PT_LOAD = 1
PT_PHDR = 6


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


def main() -> int:
    if len(sys.argv) != 2:
        die("usage: patch-elf-phdrs.py <elf>")
    path = sys.argv[1]
    with open(path, "r+b") as f:
        ehdr = f.read(64)
        if len(ehdr) < 64:
            die("ELF header too short")
        if ehdr[0:4] != b"\x7fELF":
            die("Not an ELF file")
        if ehdr[4] != 2:
            die("Not ELF64")
        if ehdr[5] != 1:
            die("Not little-endian ELF")

        (
            _e_ident,
            _e_type,
            _e_machine,
            _e_version,
            e_entry,
            e_phoff,
            _e_shoff,
            _e_flags,
            _e_ehsize,
            e_phentsize,
            e_phnum,
            _e_shentsize,
            _e_shnum,
            _e_shstrndx,
        ) = struct.unpack("<16sHHIQQQIHHHHHH", ehdr)

        if e_phentsize < 56:
            die("Unexpected program header size")
        if e_phnum == 0:
            return 0

        # Use entry point as a safe higher-half base for non-loadable PHDRs.
        high = e_entry
        if high < (1 << 63):
            return 0

        patched = 0
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            f.seek(off)
            phdr = f.read(e_phentsize)
            if len(phdr) < e_phentsize:
                break
            (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align) = struct.unpack(
                "<IIQQQQQQ", phdr[:56]
            )
            if p_type in (PT_LOAD, PT_PHDR):
                continue
            if p_vaddr < high:
                p_vaddr = high
                p_paddr = high
                new = struct.pack(
                    "<IIQQQQQQ",
                    p_type,
                    p_flags,
                    p_offset,
                    p_vaddr,
                    p_paddr,
                    p_filesz,
                    p_memsz,
                    p_align,
                )
                f.seek(off)
                f.write(new + phdr[56:])
                patched += 1

        if patched:
            print(f"patched {patched} PHDR(s) in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
