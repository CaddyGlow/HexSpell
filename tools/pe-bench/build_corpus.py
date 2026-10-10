"""Create a deterministic, redistributable PE benchmark corpus with provenance.

Generated images are structural parser inputs, not programs intended to execute.
Use --extra for locally owned real-world EXEs/DLLs; these are never downloaded.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path

import pefile


def align(value, boundary=512):
    return (value + boundary - 1) & ~(boundary - 1)


def make_image(is_64, sections, raw_size, rich=False, imports=0, exports=0, overlay=0):
    optional = 0x98
    optional_size = 240 if is_64 else 224
    header_size = align(optional + optional_size + sections * 40)
    raw_size = align(raw_size)
    virtual_stride = align(raw_size, 4096)
    data = bytearray(header_size + sections * raw_size)

    def put(offset, fmt, *values):
        struct.pack_into("<" + fmt, data, offset, *values)

    data[:2] = b"MZ"
    put(0x3C, "I", 0x80)
    data[0x80:0x84] = b"PE\0\0"
    put(
        0x84,
        "HHIIIHH",
        0x8664 if is_64 else 0x14C,
        sections,
        0x12345678,
        0,
        0,
        optional_size,
        0x22 if is_64 else 0x102,
    )
    put(
        optional,
        "HBBIII",
        0x20B if is_64 else 0x10B,
        1,
        2,
        raw_size,
        (sections - 1) * raw_size,
        0,
    )
    put(optional + 16, "II", 0x1000, 0x1000)
    image_base = 0x140000000 if is_64 else 0x400000
    if is_64:
        put(optional + 24, "Q", image_base)
    else:
        put(optional + 24, "II", 0x1000 + virtual_stride, image_base)
    put(optional + 32, "II", 4096, 512)
    put(optional + 40, "HHHHHH", 6, 0, 1, 0, 6, 0)
    put(optional + 56, "II", 0x1000 + sections * virtual_stride, header_size)
    put(optional + 68, "HH", 3, 0x140)
    put(optional + 72, "QQQQ" if is_64 else "IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    put(optional + (108 if is_64 else 92), "I", 16)
    directory_base = optional + (112 if is_64 else 96)
    for index in range(sections):
        offset = optional + optional_size + index * 40
        name = (
            b".text"
            if index == 0
            else (b".rdata" if index == 1 else f".s{index:03}".encode())
        )
        data[offset : offset + 8] = name.ljust(8, b"\0")
        put(
            offset + 8,
            "IIIIIIHHI",
            raw_size,
            0x1000 + index * virtual_stride,
            raw_size,
            header_size + index * raw_size,
            0,
            0,
            0,
            0,
            0x60000020 if index == 0 else 0x40000040,
        )
    # Only text has a nonzero pattern; directory storage begins zeroed.
    data[header_size : header_size + raw_size] = bytes(range(256)) * (raw_size // 256)
    if rich:
        base = header_size + raw_size
        rva_base = 0x1000 + virtual_stride
        cursor = 0

        def allocate(size, alignment=8):
            nonlocal cursor
            cursor = align(cursor, alignment)
            result = base + cursor
            cursor += size
            if cursor > raw_size:
                raise ValueError("directory payload exceeds section capacity")
            return result

        def rva(offset):
            return rva_base + offset - base

        def directory(index, offset, size):
            put(directory_base + index * 8, "II", rva(offset), size)

        def string(value):
            offset = allocate(len(value) + 1, 1)
            data[offset : offset + len(value)] = value
            return offset

        # An import descriptor, INT and IAT containing distinct named imports.
        descriptor = allocate(40)
        dll = string(b"KERNEL32.dll")
        width = 8 if is_64 else 4
        table = allocate((imports + 1) * width)
        iat = allocate((imports + 1) * width)
        for index in range(imports):
            if index == imports - 1:
                ordinal = (1 << (width * 8 - 1)) | 123
                put(table + index * width, "Q" if is_64 else "I", ordinal)
                put(iat + index * width, "Q" if is_64 else "I", ordinal)
                continue
            hint_name = allocate(2 + len(f"Function{index:05}") + 1, 2)
            put(hint_name, "H", index % 65536)
            name = f"Function{index:05}".encode()
            data[hint_name + 2 : hint_name + 2 + len(name)] = name
            put(table + index * width, "Q" if is_64 else "I", rva(hint_name))
            put(iat + index * width, "Q" if is_64 else "I", rva(hint_name))
        put(descriptor, "IIIII", rva(table), 0, 0, rva(dll), rva(iat))
        directory(1, descriptor, 40)
        directory(12, iat, (imports + 1) * width)

        export = allocate(40)
        dll_name = string(b"synthetic.dll")
        functions = allocate(exports * 4)
        names = allocate(exports * 4)
        ordinals = allocate(exports * 2)
        for index in range(exports):
            name = string(f"Export{index:05}".encode())
            put(functions + index * 4, "I", 0x1000 + index % raw_size)
            put(names + index * 4, "I", rva(name))
            put(ordinals + index * 2, "H", index)
        put(
            export,
            "IIHHIIIIIII",
            0,
            0x12345678,
            1,
            2,
            rva(dll_name),
            1,
            exports,
            exports,
            rva(functions),
            rva(names),
            rva(ordinals),
        )
        directory(0, export, cursor - (export - base))

        tls = allocate(40 if is_64 else 24)
        tls_data = allocate(16)
        tls_index = allocate(4)
        callbacks = allocate(width)  # Null callback array.
        put(
            tls,
            "QQQQII" if is_64 else "IIIIII",
            image_base + rva(tls_data),
            image_base + rva(tls_data + 16),
            image_base + rva(tls_index),
            image_base + rva(callbacks),
            0,
            0,
        )
        directory(9, tls, 40 if is_64 else 24)

        load = allocate(320)
        cookie_storage = allocate(width)
        put(load, "I", 320)
        put(
            load + (88 if is_64 else 60),
            "Q" if is_64 else "I",
            image_base + rva(cookie_storage),
        )
        directory(10, load, 320)

        debug = allocate(28)
        debug_data = string(
            b"RSDS" + b"\x11" * 16 + struct.pack("<I", 1) + b"synthetic.pdb"
        )
        put(debug, "IIHHIIII", 0, 0x12345678, 1, 2, 2, 38, rva(debug_data), debug_data)
        directory(6, debug, 28)

        resource_count = 8 if imports <= 8 else 64
        resource_size = 72 + resource_count * (8 + 16 + 256)
        resource = allocate(resource_size)
        put(resource, "IIHHHH", 0, 0x12345678, 1, 2, 0, 1)
        put(resource + 16, "II", 10, 0x80000000 | 24)
        put(resource + 24, "IIHHHH", 0, 0, 1, 2, 0, 1)
        put(resource + 40, "II", 1, 0x80000000 | 48)
        put(resource + 48, "IIHHHH", 0, 0, 1, 2, 0, resource_count)
        descriptors = 64 + resource_count * 8
        payloads = descriptors + resource_count * 16
        for index in range(resource_count):
            put(
                resource + 64 + index * 8, "II", 0x400 + index, descriptors + index * 16
            )
            payload = resource + payloads + index * 256
            put(
                resource + descriptors + index * 16, "IIII", rva(payload), 256, 65001, 0
            )
            data[payload : payload + 256] = bytes(range(256))
        directory(2, resource, resource_size)

        reloc = allocate(12)
        put(reloc, "IIHH", 0x1000, 12, ((10 if is_64 else 3) << 12) | 0x20, 0)
        directory(5, reloc, 12)
        if is_64:
            unwind = allocate(4)
            data[unwind : unwind + 4] = b"\x01\0\0\0"
            runtime = allocate(12)
            put(runtime, "III", 0x1000, 0x1020, rva(unwind))
            directory(3, runtime, 12)
    if overlay:
        data.extend(bytes(range(256)) * (overlay // 256))
    with pefile.PE(data=bytes(data), fast_load=True) as image:
        checksum = image.generate_checksum()
    put(optional + 64, "I", checksum)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--extra",
        type=Path,
        action="append",
        default=[],
        help="additional owned EXE/DLL; provenance is recorded",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    entries = []
    cases = [
        ("minimal", 1, 512, False, 0, 0, 0),
        ("directories", 3, 16384, True, 8, 16, 0),
        ("imports-exports", 4, 262144, True, 512, 1024, 0),
        ("many-sections", 96, 4096, False, 0, 0, 0),
        ("large-sections", 16, 262144, False, 0, 0, 0),
        ("large-overlay", 3, 512, False, 0, 0, 2097152),
    ]
    planned = {"sample1.exe", "sample2.dll", "sample64.exe"}
    planned.update(
        f"generated-{bits}-{case[0]}.exe" for bits in (32, 64) for case in cases
    )
    planned.update(
        f"external-{index:03}-{path.name}" for index, path in enumerate(args.extra)
    )
    unrelated = [
        path.name
        for path in args.output.iterdir()
        if path.suffix.lower() in (".exe", ".dll") and path.name not in planned
    ]
    if unrelated:
        parser.error(
            f"output contains unrelated PE files; choose a dedicated directory: {unrelated}"
        )

    def save(name, data, source, description):
        path = args.output / name
        path.write_bytes(data)
        with pefile.PE(data=data, fast_load=True) as image:
            image.parse_data_directories()
            entries.append(
                {
                    "file": name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "format": "PE32+" if image.PE_TYPE == 0x20B else "PE32",
                    "sections": len(image.sections),
                    "directories": [
                        entry.name
                        for entry in image.OPTIONAL_HEADER.DATA_DIRECTORY
                        if entry.VirtualAddress and entry.Size
                    ],
                    "imports": sum(
                        len(module.imports)
                        for module in getattr(image, "DIRECTORY_ENTRY_IMPORT", [])
                    ),
                    "exports": len(
                        getattr(
                            getattr(image, "DIRECTORY_ENTRY_EXPORT", None),
                            "symbols",
                            [],
                        )
                    ),
                    "source": source,
                    "description": description,
                }
            )

    root = Path(__file__).resolve().parents[2]
    for name in ("sample1.exe", "sample2.dll", "sample64.exe"):
        save(
            name,
            (root / "tests" / "samples" / name).read_bytes(),
            f"tests/samples/{name}; provenance in tests/readme.md",
            "existing compiler-produced fixture",
        )
    for is_64 in (False, True):
        for label, sections, raw, rich, imports, exports, overlay in cases:
            save(
                f"generated-{32 if not is_64 else 64}-{label}.exe",
                make_image(is_64, sections, raw, rich, imports, exports, overlay),
                "tools/pe-bench/build_corpus.py (deterministic synthetic layout)",
                label,
            )
    for index, path in enumerate(args.extra):
        save(
            f"external-{index:03}-{path.name}",
            path.read_bytes(),
            str(path.resolve()),
            "user-supplied; no redistribution implied",
        )
    (args.output / "manifest.json").write_text(
        json.dumps(
            {"schema": 1, "pefile_version": pefile.__version__, "files": entries},
            indent=2,
        )
        + "\n"
    )
    print(f"Created {len(entries)} PE files and manifest.json in {args.output}")


if __name__ == "__main__":
    main()
