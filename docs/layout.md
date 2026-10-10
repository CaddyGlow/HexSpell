# Layout accessors

Layout enums (`ProgramHeaderEntry`, `SectionHeaderEntry`, `SegmentEntry`) wrap ELF32/ELF64 or
Mach-O 32/64 variants. Use a single convention for reading and patching:

| Operation | Method | Example |
|-----------|--------|---------|
| Read value | `field(&self)` | `ph.p_offset() -> u64` |
| Patch value | `field_mut(&mut self)` | `ph.p_offset_mut() -> NumericFieldMut` |

`FieldMut` and `NumericFieldMut` expose `.value()`, `.offset()`, `.size()`, and
`.update_with(buffer, value, order)`.

## Field\<T\>

```rust
pub struct Field<T> {
    pub value: T,
    pub offset: usize,
    pub size: usize,
}
```

- `size` is always the **on-disk width**, even when `value` is promoted (e.g. `u32` stored as `u64`).
- `Field<u16/u32/u64>::update` uses little-endian (PE). Pass `ByteOrder` to `update_with` for ELF.

## FixedBytes\<N\>

Raw fixed-size blobs: PE section names (8), ELF `ei_mag` (4), Mach-O `segname` (16).

```rust
section.name.update_str(&mut pe.buffer, ".text")?;
```

## Byte order

| Format | Canonical source | Convenience |
|--------|------------------|-------------|
| ELF | `header.ei_data` (`1` = LE, `2` = BE) | `ELF::byte_order()` |
| Mach-O | magic bytes at file offset 0 | `MachO::byte_order()` |
| PE | always little-endian | n/a |

Mach-O `header.magic.value` is the normalized constant (`0xFEEDFACE`, etc.); use
`ByteOrder::from_macho_header_bytes` on the first four buffer bytes when parsing manually.

## ELF program / section headers

- [`ProgramHeaderEntry`] — `Phdr32` / `Phdr64`
- [`SectionHeaderEntry`] — `Shdr32` / `Shdr64`

ELF64 stores `p_flags` before `p_offset`; the accessors hide the layout difference.

## Mach-O segments

- [`SegmentEntry`] — `Segment32` / `Segment64`
- `name()` returns a trimmed view of `segname` bytes.
- `vmaddr_size()` returns the on-disk field width (4 or 8); it is not a duplicate read accessor.

## PE header stack

| Struct | Spec name | Notes |
|--------|-----------|-------|
| [`DosHeader`] | `IMAGE_DOS_HEADER` | `e_lfanew` points to PE signature |
| [`CoffFileHeader`] | `IMAGE_FILE_HEADER` | `number_of_sections`, `machine` |
| [`OptionalHeader`] | optional header | `magic` determines PE32 vs PE32+ |
| [`PeSection`] | section header | 40 bytes, `name` is 8 raw bytes |

[`ProgramHeaderEntry`]: crate::elf::program::ProgramHeaderEntry
[`SectionHeaderEntry`]: crate::elf::section::SectionHeaderEntry
[`SegmentEntry`]: crate::macho::segment::SegmentEntry
[`DosHeader`]: crate::pe::dos::DosHeader
[`CoffFileHeader`]: crate::pe::coff::CoffFileHeader
[`OptionalHeader`]: crate::pe::header::OptionalHeader
[`PeSection`]: crate::pe::section::PeSection

Buffer storage defaults to `Vec<u8>` for editing. Borrowed parsing uses `PE<&[u8]>`, `ELF<&[u8]>`, or `MachO<&[u8]>`; field offsets and sizes are identical to owned parsing of the same image.

Header-only access uses `ElfHeaders::header` and `MachHeaders::header`, with the same `Field` offsets/sizes as full parsing. `ElfHeaders::program` / `section` and `MachHeaders::command` preserve file-relative field positions (thin-slice-relative for Mach-O).


## Streaming field access

PE `DllImportRef::descriptor`, `ImportEntryRef` thunk/hint fields,
`NamedExportRef` name/ordinal/address slots, `FunctionExportRef::function_rva`,
`RelocationBlockRef` headers/entries, and debug iterator records retain their
original file offsets and sizes. Owned imports store descriptor fields once in
`DllImport::descriptor`; `ImportDirectory::descriptors()` borrows those fields.
Base relocations are parsed from the buffer on demand rather than cached on PE.
ELF `ProgramHeaderEntry::parse_one` and `SectionHeaderEntry::parse_one`
return the existing layout types without intermediate vector storage.
