# Changelog

<div align="center">
  <i>
    All notable changes to this project will be documented in this file.
  </i>
</div>

> **Changelog Format**
>
> - Each release is grouped by version.
> - Inside each version, changes are grouped by module in this order:
>   * General > PE > ELF > Mach-O
> - Inside each module, changes are listed by type in this order:
>   * Added > Changed > Fixed > Documentation > Chore 
>
> **Entry example:**
> ## Version
> - **Module**
>     - *Added*: Your message here using `markdown`.


## [Unreleased]

- **Mach-O**
    - *Added*: Decode every `DYLD_CHAINED_PTR_*` format from Apple's `fixup-chains.h` (arm64e userland/userland24/kernel/firmware authenticated binds and rebases, `PTR_64`, 32-bit, kernel/shared cache and segmented), `DYLD_CHAINED_IMPORT_ADDEND`/`ADDEND64` imports and multi-start pages via `decode_chained_pointer_as` and `ChainedSegment::decode_pointer`.
    - *Added*: `MachO::chained_fixup_slots` walks chains into `ChainedFixupSlot`s with the on-disk word as a `Field`, decoded pointer and `rebase_vmaddr`; `PointerAuth::discriminator` mirrors dyld's address blending.
    - *Added*: `UnixThreadCommand::program_counter` returns the `LC_UNIXTHREAD` entry PC as a `Field` for x86, x86-64, ARM, arm64 and PowerPC thread states.
    - *Changed*: **Breaking** — `ChainedSegment` stores the raw `page_start[]` table (`page_starts: Vec<u16>`, `page_count`) plus `pointer_format` and `max_valid_pointer`; use `chain_starts(page)`. `ChainedImport` gains `addend` and `library_ordinal` becomes `i32`; `ChainedFixups` gains `imports_format`. `ChainedPointer::Bind::addend` becomes `i64` and the enum gains authenticated, cache, segmented and non-pointer variants.
    - *Fixed*: Decode 8-bit chained import ordinals 128–240 as dylib ordinals instead of negative special values.
    - *Documentation*: Optional LIEF differential test for chained fixups (`tests/lief.rs`).

## [1.2.2] - 2026-10-18

- **General**
    - *Added*: Independent `pe`, `elf`, `macho`, and `common` feature flags, enabled by default; core fields/errors/byte utilities remain always available.
    - *Changed*: **Breaking** — replace `pe-write`, `elf-write`, and `macho-write` with one independent `write` feature. Combine it with the desired format flags (for example, `elf,write`); `write` does not enable formats.
    - *Changed*: **Breaking** — package version becomes 1.2.2. `default-features = false` now disables formats and the public common helper interface. Enable `pe,elf,macho,common` explicitly to retain the previous no-std surface.
    - *Chore*: Add a signature-container fuzz target and 133 deterministic PE, ELF and Mach-O seeds covering malformed containers, aliases, stacked trailers and transactional editing regressions.

- **PE**
    - *Added*: Opt-in `pe-reconstruct` feature with `pe` for `PE::from_memory_image`: reconstruct PE32/PE32+ file alignment from contiguous mapped bytes, capture virtual section contents, remap mapped debug pointers, and clear unavailable file-only metadata. Supports `no_std + alloc`; does not undo loader changes or repair imports.
    - *Added*: Owned opaque certificate tables and transactional append/replace/remove APIs with aligned serialization, directory/checksum updates and EOF/alias checks under `pe,write`.
    - *Added*: Opt-in `pe,write` feature (disabled by default) for dependency-free PE32/PE32+ construction with owned sections, builder-specific handles, resolved layouts, imports, local exports, checked fixups, base relocations, TLS, and x64 runtime-function registration.
    - *Added*: Lossless owned resource trees, canonical serialization, transactional append editing, explicit certificate preservation/stripping outcomes, and manifest/string/version/icon helpers.
    - *Added*: Linux generation examples for Hello EXEs and callable DLLs, matching Windows loaders, independent PE inspection, and Windows acceptance scripts.
    - *Fixed*: Reject inconsistent zero/nonzero security-directory pairs when reading certificates instead of reporting an unsigned image.
    - *Fixed*: Reparse the current buffer before appending certificates so stale cached directory fields cannot discard existing records.
    - *Fixed*: Mask resource-name high bits and check resource metadata/payload extents, aggregate traversal work, and certificate aliases before editing.
    - *Fixed*: `insert_section` returns `BufferOverflow` instead of panicking when the file ends before the new section header slot or `SizeOfHeaders`; nothing is modified on failure.
    - *Fixed*: Place inserted sections after complete occupied raw/virtual extents; reject invalid alignment before mutation and include header growth/overlays in insertion plans.
    - *Fixed*: Reject resource edits whose declared directory slots extend beyond the physical optional header, and reparse edited bytes before committing. Reject overflowing insertion extents before mutation and named x86 import RVAs that collide with the ordinal flag.
    - *Documentation*: Document generation, resource editing, validation, and implementation milestones.


- **ELF**
    - *Added*: Lazy modern Linux appended PKCS#7 signature parsing with on-disk metadata Fields and exact signed/payload ranges; transactional append/replace/remove under `elf,write`, preserving prefix bytes and rejecting ELF-range aliases.
    - *Added*: Opt-in `elf,write` owned Linux AMD64 construction with checked segment/section placement, symbols, fixups, zero-fill and optional section headers; explicit-layout ELF32/64 serialization in either byte order with extended-count encodings.
    - *Added*: Scoped Linux PIE/shared-object construction with explicit interpreters, versioned imports/exports, symbol visibility, eager import slots, SysV hashes, SONAME/RUNPATH and RELA pointer relocations; native loader examples and checks.
    - *Added*: Program-header fallback for stripped ELF dynamic arrays/symbols, with bounded SysV/GNU hash counts and file-backed mapping validation.
    - *Added*: Transactional nonallocated custom payload replacement/growth/addition/removal, isolated section renaming, owned notes, bounded interpreter/dynamic strings, and explicit stale/remove build-ID policies.
    - *Added*: Shared-object initializer/finalizer arrays, Linux AMD64 general-dynamic TLS, and caller-provided DWARF unwind records with a GNU EH-frame index.
    - *Fixed*: Preserve default-visible global/weak symbol preemption in generated initializer and finalizer arrays, consistently with ordinary pointer relocations.
    - *Fixed*: Preserve inner trailers when round-tripping stacked appended signatures with the `elf_signature` example.

- **Mach-O**
    - *Added*: Lazy embedded-signature command/blob access and transactional reserve/write/remove APIs under `macho,write`; final metadata is prepared before external hashing, and installation preserves every byte outside the blob.
    - *Added*: Opt-in `macho,write` thin x86-64/arm64 construction with deployment targets, symbols, entry commands, zero-fill and checked architecture fixups; macOS 13+ dyld imports/ASCII exports, chained pointer binding/rebasing, dependencies and RPATHs; output requires external signing.
    - *Added*: Transactional custom-section replacement/growth/addition with offset-consumer checks and mapped-address preservation; explicit supported signature stripping and external re-signing reports.
    - *Added*: Capacity-checked dylib/RPATH string edits, fixed-capacity FAT edits and selected-slice resizing through canonical FAT rebuilding.
    - *Added*: Ordered initializer arrays, generated libSystem termination registration, scoped Apple TLV descriptors and caller-encoded EH-frame integration; native acceptance harness signs, reparses and exercises generated images.
    - *Fixed*: Reject edits overlapping live chained bind/rebase slots; validate chain mappings, page boundaries and import ordinals. Reject unmodeled legacy runtime writes instead of treating metadata extents as complete reference coverage.
    - *Fixed*: Reject signature reservations whose load-command padding contains the `LC_MAIN` entry point.
    - *Fixed*: Bound aggregate name expansion, page-table decoding and scanning work for aliased chained-fixup metadata.

## [1.2.1] - 2026-10-11

- **General**
    - *Fixed*: Return `BufferOverflow` for integer reads whose file offsets overflow `usize`.

- **PE**
    - *Fixed*: Reject cyclic or excessively deep resource directory trees instead of overflowing the stack.

- **ELF**
    - *Fixed*: Reject overflowing extended section-table offsets instead of panicking.
    - *Fixed*: Validate init/fini array extents before reserving entry storage.
    - *Fixed*: Validate symbol table extents before reserving entry storage.

- **Mach-O**
    - *Fixed*: Reject cyclic export tries using an iterative traversal instead of overflowing the call stack.
    - *Fixed*: Validate symbol table extents before reserving entry storage.


## [1.2.0] - 2026-10-11

- **General**
    - *Added*: Borrowed `from_slice` parsing for PE, ELF, and Mach-O without copying the file buffer; owned parsing retains editing support.
    - *Added*: Borrowed string and string-pool accessors, allocation regression tests, and a dependency-free release benchmark (`cargo bench --bench parsing`).
    - *Changed*: Package version is 1.2.0; breaking migrations are documented below and in the guide.

- **PE**
    - *Added*: Streaming imports, named/function exports, relocation blocks/entries, and debug records; borrowed names and forwarders; optional immutable RVA lookup index with overlap fallback.
    - *Changed*: **Breaking** — replace eager `PE::base_relocations` with fallible `base_relocations()` and `base_relocations_iter()`; relocation errors are deferred until directory access or image-base editing.
    - *Changed*: **Breaking** — remove duplicated `ImportDirectory::descriptors` storage; use `descriptors()` or each DLL's `descriptor` field.
    - *Changed*: Validate section/export table extents before reserving capacity.
    - *Fixed*: Correct PE32 load configuration affinity, version, EditList, and security cookie offsets; correct CHPE pointer offsets, widths, and VA-to-RVA conversion.
    - *Fixed*: Correct debug directory RVA/file-pointer field ordering and preserve the full file length in checksum calculations.
    - *Fixed*: Preserve raw section alignment and payloads during section removal and optional-header growth; retain overlays during insertion and rebase COFF, certificate, section metadata, and debug file pointers during file shifts.

- **ELF**
    - *Added*: Borrowed, allocation-free header-only `ElfHeaders` parsing with program and section headers available on demand; borrowed section/symbol name accessors.
    - *Changed*: Parse individual program/section entries directly; validate table sizes before reserving capacity; section-name lookup borrows names.
- **Mach-O**
    - *Added*: Borrowed, allocation-free thin header-only `MachHeaders` parsing, single-pass command iteration, borrowed FAT metadata selection, and borrowed dylib paths.
    - *Changed*: Validate command/segment/section extents before reserving capacity. Disk-based FAT selection reads only the chosen record and thin slice.

## [1.1.2] - 2026-10-10

- **PE**
    - *Fixed*: Read the PE32+ load configuration security cookie at byte 88 after the eight-byte EditList; reject declared structures shorter than the cookie and check extent arithmetic.
    - *Fixed*: Reject overflowing TLS directory offsets for both PE32 and PE32+ instead of panicking.


## [1.1.1] - 2026-10-08

- **PE**
    - *Fixed*: Bound certificate headers, payloads and aligned record steps by the declared security directory; reject inconsistent empty directories and overflowing offsets.
- **General**
    - *Documentation*: Point crate metadata at the maintained CaddyGlow fork and caddy-hexspell documentation.


## [1.0.0] - 2026-07-07

- **General**
    - *Added*: `FixedBytes<N>` type and `Field<FixedBytes<N>>::update` / `update_str` for on-disk byte fields.
    - *Added*: `ByteOrder::from_ei_data` (alias of `from_elf_data`) and `ByteOrder::from_macho_header_bytes`.
    - *Added*: `NumericFieldMut` and `FieldMut` accessors for layout enums (patch semantics without raw `Field` copies).
    - *Added*: `ByteOrder::read_u16/u32/u64` and `write_u16/u32/u64` helpers for parsers.
    - *Added*: Cross-format modules `strings`, `validation`, `reloc`, and `write` (name pools, overlap checks, reloc listing, dry-run layout planner).
    - *Changed*: **Breaking** — single `field::ByteOrder` type; removed `elf::header::Endianness` and `macho::header::Endianness`.
- **PE**
    - *Added*: `DosHeader` (`IMAGE_DOS_HEADER`) and `CoffFileHeader` (`IMAGE_FILE_HEADER`) with full `Field` mapping.
    - *Added*: `PE::architecture()` alias delegating to `coff_header.machine`.
    - *Added*: `OptionalHeader::magic: Field<u16>` and `OptionalHeader::pe_type()` derived from magic.
    - *Added*: `OptionalHeader::active_data_directory_count` / `has_data_directory`; parse respects `number_of_rva_and_sizes`.
    - *Added*: `NewSection`, `insert_section`, `insert_section_raw`; section flag constants (`CODE`, `READ`, `EXECUTE`, etc.).
    - *Added*: Full import/export tables, bound import, delay-load import, TLS, exceptions, COFF symbols, section COFF relocs, load config, debug directory, resource tree.
    - *Added*: `relocation::apply_base_relocations`, `PE::apply_image_base`, `sync_data_directory_rva` / `sync_data_directory_size`.
    - *Added*: Rich header, Authenticode certificate table (read-only), CLR `IMAGE_COR20_HEADER`, ARM64x/CHPE architecture data, COFF line numbers.
    - *Added*: Structural helpers — `layout::rename_section`, `remove_section`, `grow_optional_header`, `sync_layout`.
    - *Changed*: **Breaking** — `PE` exposes `dos_header`, `coff_header`, `optional_header`; `architecture` and `number_of_sections` removed from optional header (COFF is canonical).
    - *Changed*: **Breaking** — `PeSection.name` is `Field<FixedBytes<8>>` (use `name_str()` for display).
    - *Changed*: **Breaking** — removed `generate_section_header` and `add_section` (use `insert_section`).
    - *Changed*: `rva_to_offset` maps only RVAs covered by `SizeOfRawData` (file-backed ranges).
- **ELF**
    - *Added*: `ElfHeader` fields `ei_mag`, `ei_class`, `ei_data`, `ei_version`, `ei_pad` as canonical `Field`s.
    - *Added*: `ElfHeader::class()` helper derived from `ei_class`.
    - *Added*: `ProgramHeaderEntry` (`Phdr32` / `Phdr64`) and `SectionHeaderEntry` (`Shdr32` / `Shdr64`) with field accessors.
    - *Added*: `ELF::byte_order()`, `insert_section`, `insert_pt_load`, `NewSection`, `NewPtLoad`.
    - *Added*: Section semantics, program header typing, symbol tables, `.dynamic`, `.rel` / `.rela` relocations.
    - *Added*: `.hash` / `.gnu.hash`, GNU version tables, notes / `.note.gnu.property`, unwind blobs, COMDAT groups, init/fini arrays.
    - *Added*: PLT/GOT linkage views, `relocation::apply_rela`, structural helpers (arbitrary insert, `PT_LOAD` sync, segment split/merge, `e_shnum == 0`).
    - *Added*: Minimal `ar` archive reader and `ET_CORE` detection.
    - *Changed*: **Breaking** — removed `ELF.byte_order` field and `ElfHeader.ident` / `ElfHeader.class` fields; `byte_order()` returns `Result` from `header.ei_data`.
    - *Changed*: **Breaking** — `program_headers` and `section_headers` use layout enums; `header.endianness` removed (use `elf.byte_order()`).
    - *Changed*: layout field API — read `ph.p_offset()`, patch `ph.p_offset_mut()` (removed `*_value()` duplicates).
- **Mach-O**
    - *Added*: `SegmentEntry` (`Segment32` / `Segment64`) with field accessors; `MachO::byte_order()`, `insert_segment`, `NewSegment`.
    - *Added*: Typed load commands (`LC_BUILD_VERSION`, `LC_SOURCE_VERSION`, `LC_VERSION_MIN_*`, `LC_UNIXTHREAD`, linker options, fileset entry).
    - *Added*: Section relocations, export trie and bind opcode decoders, `__LLVM` bitcode detection.
    - *Added*: FAT thin slice (`slice_ref`), build/merge, `from_fat_index_read`.
    - *Added*: Structural helpers — `insert_load_command_at`, `remove_load_command`, `add_section`, code-signature alignment preservation.
    - *Changed*: **Breaking** — removed `MachO.byte_order` field; `byte_order()` derives from header magic bytes on disk.
    - *Changed*: **Breaking** — segment `segname: Field<FixedBytes<16>>` replaces `name: String` (`name()` remains as view).
    - *Changed*: **Breaking** — `segments` use `SegmentEntry`; `header.endianness` removed (use `macho.byte_order()`).
    - *Changed*: layout field API — read `seg.vmaddr()`, patch `seg.vmaddr_mut()` (removed `*_value()` duplicates).
- **Documentation**
    - *Added*: `docs/coverage.md` coverage matrix; cross-format section in `docs/guide.md`.
    - *Changed*: Crate-level rustdoc examples for PE, ELF, and Mach-O in `lib.rs`.

## [0.0.5](https://github.com/M3str3/HexSpell/pull/10) - 2025-08-07

- **General**
    - *Added*: Added comprehensive tests for `Field<String>` covering padding, exact fit, overflow, and UTF-8 multibyte handling in section names (see `tests/general.rs`).
    - *Added*: Added tests for `Field<number>` updates verifying successful writes and `FileParseError::ValueTooLarge` errors.
    - *Changed*: `Field<number>::update` now returns `Result` and errors with `FileParseError::ValueTooLarge` if the value does not fit.
    - *Changed*: `Field<String>::update` now accepts `&str` instead of `&String`, reducing unnecessary allocations when updating string fields.
    - *Fixed*: Improved `Field<String>::update` to ensure that when the new value is shorter than the field size, any leftover bytes are properly zeroed out, and UTF-8 multibyte strings are handled correctly. In previous versions, some bytes from the old value could remain in the binary.
    - *Documentation*: Expanded module-level documentation with detailed headers across core modules and tests.
- **PE**
    - *Added*: Added tests for successful and failing writes for **PE** files.
    - *Changed*: Updated internal calls to `Field<number>::update` to propagate `FileParseError::ValueTooLarge` errors.
- **ELF**
    - *Added*: Added `write_file` method for **ELF** format, providing a consistent read/write interface across all formats.
    - *Added*: Added tests for successful and failing writes for **ELF** files.
    - *Added*: Detect `endianness` from header and parse program and section headers with the appropriate byte order. A new value `elf::header::endianness` now exists.
    - *Added*: Added tests for valid and invalid **ELF** headers to ensure `endianness` is handled correctly.
- **Mach-O**
    - *Added*: Added `write_file` method for **Mach-O** format, providing a consistent read/write interface across all formats.
    - *Added*: Added tests for successful and failing writes for **Mach-O** files.
    - *Added*: Detect **Mach-O** endianness from the header and parse load commands and segments with the appropriate byte order, including tests for valid and invalid big-endian headers. A new value `macho::header::endianness` now exists.
    - *Added*: Support parsing **FAT** **Mach-O** binaries and add tests for little-endian and **FAT** headers.
    - *Fixed* [#4](https://github.com/M3str3/HexSpell/issues/4): When adding a new section via `add_section`, ensure `sizeofheaders` grows (and is aligned to `filealignment`) if the section doesn’t fit, shifting the rest of the file (including the entry point) accordingly. ([#4](https://github.com/M3str3/HexSpell/issues/4))

## [0.0.2](https://github.com/M3str3/HexSpell/pull/3) - 2024-09-14

- **General**
    - *Added*: New examples for **PE**, **ELF** and **Mach-O** in `README.md`.
    - *Added*: Added `rustfmt.toml` to define project-wide formatting rules and ran `cargo fmt`.
    - *Changed*: Refactored utility functions to use `Iterator::map` for byte conversions.
    - *Changed*: Updated `Field` struct to accept `&mut [u8]` instead of `Vec<u8]`.
    - *Changed*: Removed unnecessary type conversions in the **PE** code.
    - *Fixed*: Corrected typos and spelling mistakes throughout the codebase.
    - *Documentation*: Expanded `tests/readme.md` with more examples and explanations.
    - *Documentation*: Introduced a generator script to automate creation of `tests.toml`.
- **PE**
    - *Changed*: Replaced `to_string` calls with `fmt::Display` implementations for cleaner formatting.
- **ELF**
    - *Changed*: Simplified tests to use `is_empty()` instead of comparing with `!= ""`.
- **Mach-O**
    - *Added*: Initial support.
    - *Added*: Basic unit tests.
    - *Added*: Additional test binary.

## [0.0.1](https://github.com/M3str3/HexSpell/pull/2) - 2024-05-22

- **PE (Portable Executable)**
    - *Added*: Initial support.
    - *Added*: Core parsing functionality for headers.
    - *Added*: Basic unit tests.
    - *Added*: Additional test binaries (**EXE** and **DLL**) and their source code.
- **ELF (Executable and Linkable Format)**
    - *Added*: Initial support.
    - *Added*: Core parsing functionality for headers.
    - *Added*: Basic unit tests.
    - *Added*: Additional test binary and its source code.
