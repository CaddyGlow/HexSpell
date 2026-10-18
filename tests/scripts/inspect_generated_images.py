#!/usr/bin/env python3
"""Independent structural checks for generated ELF64 and thin Mach-O images.

Uses only Python's standard library. It does not establish macOS runtime support.
"""
import argparse
import pathlib
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect_elf(data):
    require(data[:7] == b'\x7fELF\x02\x01\x01', 'expected ELF64 little endian')
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    require(kind in (2, 3) and machine == 62 and version == 1, 'unsupported ELF profile')
    require(ehsize == 64 and phsize == 56, 'invalid ELF header sizes')
    loads = []
    seen_load = False
    for i in range(phnum):
        ptype, perms, offset, va, pa, filesz, memsz, alignment = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
        require(offset + filesz <= len(data), 'program extent outside file')
        if ptype in (3, 6):
            require(not seen_load, 'INTERP/PHDR must precede LOAD headers')
        if ptype == 1:
            seen_load = True
            require(filesz <= memsz, 'load filesz exceeds memsz')
            require(alignment > 0 and alignment & (alignment - 1) == 0, 'invalid load alignment')
            require(va % alignment == offset % alignment, 'incongruent load alignment')
            require(perms & 3 != 3, 'writable executable mapping')
            loads.append((va, va + memsz, offset, filesz, perms))
    require(loads == sorted(loads), 'load segments out of order')
    require(all(a[1] <= b[0] for a, b in zip(loads, loads[1:])), 'overlapping load segments')
    require(any(offset == 0 and size >= phoff + phnum * phsize for _, _, offset, size, _ in loads), 'headers not mapped')
    if kind == 2 or entry:
        require(any(va <= entry < va + size and perms & 1 for va, _, _, size, perms in loads), 'entry not initialized executable bytes')
    if shoff:
        require(shsize == 64 and shnum and shstr < shnum, 'invalid section table')
        require(shoff + shsize * shnum <= len(data), 'section table outside file')
        require(data[shoff:shoff + shsize] == bytes(shsize), 'nonzero null section')
        for i in range(shnum):
            name, stype, sflags, va, offset, size, link, info, alignment, entsize = struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
            if stype != 8:
                require(offset + size <= len(data), 'section outside file')
    else:
        require(shnum == 0 and shstr == 0, 'sectionless header inconsistency')
    print(f'ELF64 AMD64 kind={kind}, entry={entry:#x}, loads={len(loads)}, sections={shnum}')


def inspect_macho(data):
    magic, cpu, subtype, kind, ncmds, sizeofcmds, flags, reserved = struct.unpack_from('<8I', data)
    require(magic == 0xfeedfacf and cpu in (0x1000007, 0x100000c), 'unsupported Mach-O profile')
    require(kind in (2, 6), 'expected executable or dylib')
    end = 32 + sizeofcmds
    require(end <= len(data), 'load commands outside file')
    pos = 32
    entry = None
    segments = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, pos)
        require(size >= 8 and size % 8 == 0 and pos + size <= end, 'invalid command extent')
        if cmd == 0x19:
            name, va, vmsize, offset, filesz, maxprot, prot, count, segflags = struct.unpack_from('<16sQQQQIIII', data, pos + 8)
            require(size == 72 + 80 * count, 'segment command size mismatch')
            require(filesz <= vmsize and offset + filesz <= len(data), 'invalid segment extent')
            require(prot & 6 != 6 and prot & ~maxprot == 0, 'invalid segment permissions')
            segments.append((va, va + vmsize, offset, filesz, prot))
            for i in range(count):
                section = pos + 72 + i * 80
                sectname, segname, addr, length, segoff, align, reloff, nreloc, sflags, r1, r2, r3 = struct.unpack_from('<16s16sQQ8I', data, section)
                require(segname == name, 'section segment identity mismatch')
                require(va <= addr and addr + length <= va + vmsize, 'section outside virtual segment')
                if sflags & 0xff not in (1, 12, 18):
                    require(offset <= segoff and segoff + length <= offset + filesz, 'section outside file segment')
        elif cmd == 0x80000028:
            require(size == 24, 'invalid LC_MAIN size')
            entry = struct.unpack_from('<Q', data, pos + 8)[0]
        elif cmd == 2:
            symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', data, pos + 8)
            require(symoff + 16 * nsyms <= len(data) and stroff + strsize <= len(data), 'invalid symbol table extents')
        pos += size
    require(pos == end, 'command count/size disagreement')
    require(all(a[1] <= b[0] for a, b in zip(segments, segments[1:])), 'overlapping segments')
    if entry is not None:
        require(any(offset <= entry < offset + size and prot & 4 for _, _, offset, size, prot in segments), 'entry outside initialized executable segment')
    print(f'Mach-O64 cpu={cpu:#x}, kind={kind}, commands={ncmds}; structural validation only')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=pathlib.Path)
    args = parser.parse_args()
    data = args.image.read_bytes()
    if data.startswith(b'\x7fELF'):
        inspect_elf(data)
    else:
        inspect_macho(data)


if __name__ == '__main__':
    main()
