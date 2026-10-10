"""Independent pefile reports for HexSpell's opt-in differential tests.

Image mode parses an actual PE. Record mode uses pefile's own format definitions
to decode standalone structures without requiring valid referenced RVAs.
"""

import argparse
import json
import struct
import sys

import pefile

# pefile has no native definitions for these records. Keep the PE/COFF SDK
# schemas visibly separate from pefile's own formats (see verification docs).
SDK_FORMATS = {
    "SDK_IMAGE_SYMBOL": (
        "IMAGE_SYMBOL",
        (
            "8s,Name",
            "I,Value",
            "h,SectionNumber",
            "H,Type",
            "B,StorageClass",
            "B,NumberOfAuxSymbols",
        ),
    ),
    "SDK_IMAGE_RELOCATION": (
        "IMAGE_RELOCATION",
        ("I,VirtualAddress", "I,SymbolTableIndex", "H,Type"),
    ),
    "SDK_IMAGE_LINENUMBER": ("IMAGE_LINENUMBER", ("I,Type", "H,Linenumber")),
    "SDK_WIN_CERTIFICATE": (
        "WIN_CERTIFICATE",
        ("I,dwLength", "H,wRevision", "H,wCertificateType"),
    ),
    "SDK_COR20_HEADER": (
        "IMAGE_COR20_HEADER",
        (
            "I,cb",
            "H,MajorRuntimeVersion",
            "H,MinorRuntimeVersion",
            "I,MetaDataRVA",
            "I,MetaDataSize",
            "I,Flags",
            "I,EntryPointToken",
            "I,ResourcesRVA",
            "I,ResourcesSize",
            "I,StrongNameSignatureRVA",
            "I,StrongNameSignatureSize",
            "I,CodeManagerTableRVA",
            "I,CodeManagerTableSize",
            "I,VTableFixupsRVA",
            "I,VTableFixupsSize",
            "I,ExportAddressTableJumpsRVA",
            "I,ExportAddressTableJumpsSize",
            "I,ManagedNativeHeaderRVA",
            "I,ManagedNativeHeaderSize",
        ),
    ),
}


def emit(key, value, offset, width):
    print(f"[{json.dumps(key)}]")
    text = value.hex() if isinstance(value, bytes) else str(value)
    print(f"value = {json.dumps(text)}")
    print(f"offset = {offset}")
    print(f"size = {width}")


def report(prefix, record, fmt):
    for definition in fmt[1]:
        encoding, *names = definition.split(",")
        width = struct.calcsize("<" + encoding)
        for name in names:
            value = getattr(record, name)
            offset = record.get_field_absolute_offset(name)
            if prefix == "dos" and name in ("e_res", "e_res2"):
                for index in range(width // 2):
                    emit(
                        f"{prefix}.{name}[{index}]",
                        struct.unpack_from("<H", value, index * 2)[0],
                        offset + index * 2,
                        2,
                    )
            else:
                emit(f"{prefix}.{name}", value, offset, width)
            if prefix == "record" and name == "EditList" and width == 8:
                # HexSpell preserves a legacy low-DWORD accessor, not a full EditList.
                emit(f"{prefix}.EditList.low32", value & 0xFFFFFFFF, offset, 4)


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["image", "record"])
parser.add_argument("--format")
parser.add_argument("--offset", type=int, default=0)
parser.add_argument("--directories", action="store_true")
args = parser.parse_args()
data = sys.stdin.buffer.read()

if args.mode == "record":
    fmt = (
        SDK_FORMATS[args.format]
        if args.format in SDK_FORMATS
        else getattr(pefile.PE, f"__{args.format}_format__")
    )
    record = pefile.Structure(fmt, file_offset=args.offset)
    # Versioned load-config records can be shorter than pefile's current schema.
    payload = data[args.offset :]
    record.__unpack__(payload.ljust(record.sizeof(), b"\0"))
    report("record", record, fmt)
else:
    with pefile.PE(data=data, fast_load=True) as image:
        report("dos", image.DOS_HEADER, image.__IMAGE_DOS_HEADER_format__)
        report("coff", image.FILE_HEADER, image.__IMAGE_FILE_HEADER_format__)
        optional_fmt = (
            image.__IMAGE_OPTIONAL_HEADER64_format__
            if image.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
            else image.__IMAGE_OPTIONAL_HEADER_format__
        )
        report("optional", image.OPTIONAL_HEADER, optional_fmt)
        for index, directory in enumerate(image.OPTIONAL_HEADER.DATA_DIRECTORY):
            report(
                f"directory{index}", directory, image.__IMAGE_DATA_DIRECTORY_format__
            )
        for index, section in enumerate(image.sections):
            report(f"section{index}", section, image.__IMAGE_SECTION_HEADER_format__)
            emit(
                f"payload{index}",
                section.get_data(),
                section.PointerToRawData,
                section.SizeOfRawData,
            )
            if section.SizeOfRawData:
                emit(
                    f"mapping{index}",
                    image.get_offset_from_rva(section.VirtualAddress),
                    0,
                    0,
                )
        emit("checksum", image.generate_checksum(), 0, 0)
        emit("section_count", len(image.sections), 0, 0)
        if args.directories:
            image.parse_data_directories()
            modules = getattr(image, "DIRECTORY_ENTRY_IMPORT", [])
            emit("import_count", len(modules), 0, 0)
            for module_index, module in enumerate(modules):
                prefix = f"import{module_index}"
                report(
                    f"{prefix}.descriptor",
                    module.struct,
                    image.__IMAGE_IMPORT_DESCRIPTOR_format__,
                )
                emit(f"{prefix}.dll", module.dll, module.struct.Name, 0)
                emit(f"{prefix}.count", len(module.imports), 0, 0)
                for index, entry in enumerate(module.imports):
                    fmt = (
                        image.__IMAGE_THUNK_DATA64_format__
                        if image.PE_TYPE == 0x20B
                        else image.__IMAGE_THUNK_DATA_format__
                    )
                    report(f"{prefix}.thunk{index}", entry.struct_table, fmt)
                    if entry.name is not None:
                        emit(
                            f"{prefix}.name{index}",
                            entry.name,
                            entry.name_offset,
                            len(entry.name),
                        )
                        emit(
                            f"{prefix}.hint{index}",
                            entry.hint,
                            entry.name_offset - 2,
                            2,
                        )
                    else:
                        emit(
                            f"{prefix}.ordinal{index}",
                            entry.ordinal,
                            entry.thunk_offset,
                            0,
                        )
            exports = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
            emit("has_exports", int(exports is not None), 0, 0)
            if exports:
                report(
                    "export", exports.struct, image.__IMAGE_EXPORT_DIRECTORY_format__
                )
                for index in range(exports.struct.NumberOfFunctions):
                    offset = image.get_offset_from_rva(
                        exports.struct.AddressOfFunctions + index * 4
                    )
                    emit(
                        f"export.function{index}",
                        image.get_dword_from_offset(offset),
                        offset,
                        4,
                    )
                named_index = 0
                for symbol in exports.symbols:
                    if symbol.name is None:
                        continue
                    emit(
                        f"export.name{named_index}",
                        symbol.name,
                        symbol.name_offset,
                        len(symbol.name),
                    )
                    offset = image.get_offset_from_rva(
                        exports.struct.AddressOfNames + named_index * 4
                    )
                    emit(
                        f"export.name_rva{named_index}",
                        image.get_dword_from_offset(offset),
                        offset,
                        4,
                    )
                    offset = image.get_offset_from_rva(
                        exports.struct.AddressOfNameOrdinals + named_index * 2
                    )
                    emit(
                        f"export.ordinal_index{named_index}",
                        image.get_word_from_offset(offset),
                        offset,
                        2,
                    )
                    named_index += 1
                emit("export.named_count", named_index, 0, 0)
