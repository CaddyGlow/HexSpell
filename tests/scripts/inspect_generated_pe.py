#!/usr/bin/env python3
"""Independent structural acceptance of HexSpell's EXE/DLL examples.

Requires pefile==2024.8.26. This deliberately does not import HexSpell or its
planner and cannot replace Windows loader/ABI/runtime tests.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile


def inspect(path, arch, kind):
    data = path.read_bytes()
    pe = pefile.PE(data=data)
    pe.parse_data_directories()
    is64 = arch == "x64"
    width = 8 if is64 else 4
    base = pe.OPTIONAL_HEADER.ImageBase
    assert pe.FILE_HEADER.Machine == (0x8664 if is64 else 0x14C)
    assert pe.OPTIONAL_HEADER.Magic == (0x20B if is64 else 0x10B)
    assert bool(pe.FILE_HEADER.Characteristics & 0x2000) == (kind == "dll")
    assert pe.FILE_HEADER.Characteristics & 2
    assert not pe.FILE_HEADER.Characteristics & 1, "relocations stripped"
    assert pe.OPTIONAL_HEADER.DllCharacteristics & 0x40, "ASLR not enabled"
    assert pe.OPTIONAL_HEADER.CheckSum == pe.generate_checksum()
    assert pe.FILE_HEADER.TimeDateStamp == 0
    assert pe.OPTIONAL_HEADER.SizeOfHeaders % pe.OPTIONAL_HEADER.FileAlignment == 0

    def backed(rva, size):
        for section in pe.sections:
            offset = rva - section.VirtualAddress
            if 0 <= offset and offset + size <= section.SizeOfRawData:
                start = section.PointerToRawData + offset
                assert start + size <= len(data)
                return section, start
        raise AssertionError(f"unbacked range {rva:#x}+{size:#x}")

    def pointer(rva):
        _, offset = backed(rva, width)
        return struct.unpack_from("<Q" if is64 else "<I", data, offset)[0]

    raw_ranges = []
    virtual_end = pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in pe.sections:
        assert section.VirtualAddress % pe.OPTIONAL_HEADER.SectionAlignment == 0
        if section.SizeOfRawData:
            assert section.PointerToRawData % pe.OPTIONAL_HEADER.FileAlignment == 0
            assert section.SizeOfRawData % pe.OPTIONAL_HEADER.FileAlignment == 0
            assert section.PointerToRawData >= pe.OPTIONAL_HEADER.SizeOfHeaders
            end = section.PointerToRawData + section.SizeOfRawData
            assert end <= len(data)
            raw_ranges.append((section.PointerToRawData, end))
        virtual_end = max(virtual_end, section.VirtualAddress + max(
            section.Misc_VirtualSize, section.SizeOfRawData))
    raw_ranges.sort()
    assert all(a[1] <= b[0] for a, b in zip(raw_ranges, raw_ranges[1:]))
    alignment = pe.OPTIONAL_HEADER.SectionAlignment
    assert pe.OPTIONAL_HEADER.SizeOfImage == (virtual_end + alignment - 1) & -alignment
    section, _ = backed(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 1)
    assert section.Characteristics & 0x20000000

    assert hasattr(pe, "DIRECTORY_ENTRY_BASERELOC")
    relocations = {}
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        assert block.struct.VirtualAddress % 4096 == 0
        assert block.struct.SizeOfBlock % 4 == 0
        for entry in block.entries:
            if entry.type:
                assert entry.type == (10 if is64 else 3)
                assert entry.rva not in relocations
                backed(entry.rva, width)
                relocations[entry.rva] = pointer(entry.rva)
    assert relocations, "examples must exercise absolute pointer relocation"

    if kind == "exe":
        assert pe.OPTIONAL_HEADER.Subsystem == 2
        imports = {
            item.dll.decode("ascii").upper(): {
                symbol.name.decode("ascii") if symbol.name else symbol.ordinal
                for symbol in item.imports
            }
            for item in pe.DIRECTORY_ENTRY_IMPORT
        }
        assert "MessageBoxW" in imports["USER32.DLL"]
        assert "ExitProcess" in imports["KERNEL32.DLL"]
        iat = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12]
        assert iat.VirtualAddress and iat.Size
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            for symbol in dll.imports:
                rva = symbol.address - base
                section, _ = backed(rva, width)
                assert section.Characteristics & 0x80000000
                assert iat.VirtualAddress <= rva < iat.VirtualAddress + iat.Size
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
        assert directory.Size == (40 if is64 else 24)
        assert tls.EndAddressOfRawData >= tls.StartAddressOfRawData
        backed(tls.StartAddressOfRawData - base,
               tls.EndAddressOfRawData - tls.StartAddressOfRawData)
        section, _ = backed(tls.AddressOfIndex - base, 4)
        assert section.Characteristics & 0x80000000
        assert tls.SizeOfZeroFill == 0
        for index in range(4):
            site = directory.VirtualAddress + width * index
            assert site in relocations
        callbacks_rva = tls.AddressOfCallBacks - base
        callback = pointer(callbacks_rva)
        assert callback and pointer(callbacks_rva + width) == 0
        assert callbacks_rva in relocations
        assert callbacks_rva + width not in relocations
        section, _ = backed(callback - base, 1)
        assert section.Characteristics & 0x20000000
        if is64:
            assert hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION")
            assert any(record.struct.BeginAddress <= pe.OPTIONAL_HEADER.AddressOfEntryPoint
                       < record.struct.EndAddress
                       for record in pe.DIRECTORY_ENTRY_EXCEPTION)
            for record in pe.DIRECTORY_ENTRY_EXCEPTION:
                backed(record.struct.UnwindData, 4)
    else:
        exports = pe.DIRECTORY_ENTRY_EXPORT
        assert exports.struct.Base == 1
        assert exports.struct.NumberOfFunctions == 3
        assert exports.struct.NumberOfNames == 2
        assert [(symbol.name, symbol.ordinal) for symbol in exports.symbols] == [
            (b"Add", 1), (b"GetGreeting", 2), (None, 3)]
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        for symbol in exports.symbols:
            assert symbol.forwarder is None
            section, _ = backed(symbol.address, 1)
            assert section.Characteristics & 0x20000000
            assert not (directory.VirtualAddress <= symbol.address
                        < directory.VirtualAddress + directory.Size)
    warnings = pe.get_warnings()
    # Small synthetic images contain mostly alignment padding. Accept that
    # heuristic while rejecting warnings about malformed PE structures.
    assert all(warning.startswith("Byte 0x00 makes up ") for warning in warnings), warnings
    result = {"file": str(path), "arch": arch, "kind": kind,
              "sha256": hashlib.sha256(data).hexdigest(),
              "sections": len(pe.sections), "relocations": len(relocations),
              "preferred_base": hex(base), "warnings": warnings}
    pe.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=["x86", "x64"], required=True)
    parser.add_argument("--kind", choices=["exe", "dll"], required=True)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.file, args.arch, args.kind), indent=2))


if __name__ == "__main__":
    main()
