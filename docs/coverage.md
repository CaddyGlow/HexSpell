# Coverage matrix

What HexSpell models today versus known gaps. “Modeled” means the on-disk layout is exposed as
[`Field`] values with real `offset` / `size` (see [guide.md](guide.md)). “Lazy” parsers run on
method call; “Eager” structures are filled during `from_buffer`.

## PE (Windows)

| Area | Status | Access | Notes |
|------|--------|--------|-------|
| DOS / COFF / optional header P0 | Modeled | Eager on `PE::from_buffer` | PE32 + PE32+ |
| Data directories (16 indices) | Modeled | Eager | Gated by `number_of_rva_and_sizes` |
| Section table | Modeled | Eager | `PeSection`, `insert_section` |
| Memory image reconstruction | Scoped (`pe,pe-reconstruct`) | `PE::from_memory_image` | Contiguous RVA-addressed PE32/PE32+ snapshots; file-aligned sections, captured virtual tails, mapped debug pointer repair, file-only metadata stripping; SectionAlignment >= 4096; no import repair or relocation reversal |
| Imports / IAT / hint-name | Modeled | Lazy — `PE::imports` | |
| Exports | Modeled | Lazy — `PE::exports` | Forwarders, ordinals |
| Base relocations | Modeled | Lazy — `PE::base_relocations()` / `base_relocations_iter` | Current buffer; no cache |
| Section COFF relocs | Modeled | Lazy — `PE::section_relocations` | |
| TLS / exceptions / debug / resources | Modeled | Lazy | |
| COFF symbol table + strtab | Modeled | Lazy — `PE::coff_symbols` | Long section names via `strings::pe_section_name` |
| Bound / delay-load imports | Modeled | Lazy | |
| Load config (base fields) | Modeled | Lazy | Cookie at byte 60 (PE32) / 88 (PE32+); Size >= 64 / 96, with the full declared extent present. Affinity is modeled in both layouts. Larger versions accepted; trailing fields generally unmodeled. |
| Rich header / certs / CLR / ARM64x | Modeled | Lazy — `rich_header`, `certificates`, `clr`, `architecture_data` | Certificates expose bounded opaque records |
| Line numbers (COFF) | Modeled | Lazy — `section_linenumbers` | |
| Section rename / remove / layout sync | Partial | `layout::rename_section`, `remove_section`, `sync_layout` | Aligned raw data and overlay/file-pointer preservation tested against pefile. Embedded code/data RVAs and entry-point rebuilding after middle-section removal remain partial. |
| PE32 / PE32+ construction | Supported (`pe,write`) | `build::PeBuilder` | Owned sections/symbols, checked layout, imports, local exports, fixups/base relocations, TLS, caller-supplied x64 unwind data; returns ordinary `PE` |
| Resource payloads / owned trees | Supported (`pe,write`) | `ResourceDataEntry::payload`, `PE::owned_resources` | Complete file-backed extents; raw UTF-16 keys and unknown payloads preserved |
| Resource serialization / editing | Supported (`pe,write`) | `ResourceDirectoryOwned::serialize`, `PE::replace_resources` | Transactional append; existing RVAs retained; explicit signature policy; no compaction |
| Typed resources | Partial (`pe,write`) | `resource::{Manifest, strings, version, icon}` | String blocks/languages, nested version blocks, ICO/group IDs; other types remain opaque |

| Certificate table editing | Scoped (`pe,write`) | `owned_certificates`, `append_certificate`, `replace_certificates`, `remove_certificates` | Lossless owned records, aligned serialization, isolated EOF tables, directory/checksum updates; no cryptography |

## ELF (Linux / BSD)

| Area | Status | Access | Notes |
|------|--------|--------|-------|
| Ehdr / Phdr / Shdr | Modeled | Eager | ELF32 + ELF64, BE + LE |
| Section names / `section_data` | Modeled | Lazy / view | `.shstrtab` resolution |
| `.symtab` / `.dynsym` | Modeled | Lazy | `ELF::symbols`, `ELF::dynamic_symbols`; stripped dynamic symbols use PT_DYNAMIC and bounded SysV/GNU hash counts |
| `.dynamic` | Modeled | Lazy — `ELF::dynamic` | `DT_*` tags; PT_DYNAMIC fallback when section metadata is absent |
| `.rel` / `.rela` | Modeled | Lazy — `ELF::relocations` | |
| `.hash` / `.gnu.hash` / GNU version | Modeled | Lazy | `sysv_hash`, `gnu_hash`, `version_*` |
| Notes / `.note.gnu.property` | Modeled | Lazy — `note_sections`, `gnu_property_notes` | |
| Unwind / exception blobs | Modeled | Lazy — `eh_frame`, `gcc_except_table` | |
| `insert_section` / `insert_pt_load` | Modeled | Structural helpers | Arbitrary offset, `e_shnum == 0` |
| RELA apply helper | Modeled | `relocation::apply_rela` | |
| PLT/GOT linkage | Modeled | Lazy — `plt_got_sections` | |
| Linux AMD64 construction | Scoped (`elf,write`) | `build::ElfBuilder` | Static/PIE/shared images, symbols/fixups, zero-fill, optional section table, versioned eager imports/exports, visibility, RELA, SysV hash, SONAME/RUNPATH |
| Structural ELF serialization | Supported (`elf,write`) | `build::layout::serialize_layout` | Caller-positioned ELF32/64 in either byte order, class-width checks and extended-count/section-name-index encodings; no ABI/linkage synthesis |
| Loader lifecycle / TLS / unwind generation | Scoped (`elf,write`) | `add_initializer`, `add_finalizer`, `add_tls_template`, `add_tls_address_slot`, `add_eh_frame` | Shared-object lifecycle; Linux AMD64 general-dynamic TLS; caller CIE/FDE records plus GNU EH-frame index |
| Custom-data / loader-string editing | Scoped (`elf,write`) | `edit::ElfEdit` | Replace/grow/add/remove isolated nonallocated data, rename, owned notes, bounded interpreter/NEEDED/SONAME/RUNPATH; explicit stale/remove build-ID policy; mapped VAs preserved |

| Appended Linux signatures | Scoped | `appended_signature`, `signature::AppendedSignature`; `set_appended_signature`, `remove_appended_signature` with `elf,write` | Modern PKCS#7 trailer, big-endian length, bounded opaque data and exact signed prefix, transactional alias-checked replacement/removal; no cryptography or kernel trust |

## Mach-O (macOS)

| Area | Status | Access | Notes |
|------|--------|--------|-------|
| `mach_header` / load cmd headers | Modeled | Eager | |
| Typed LC (segment, symtab, dyld, dylib, …) | Modeled | Lazy — `typed_commands` | |
| `section` / `section_64` | Modeled | Eager under segments | |
| Symbols + strtab | Modeled | Lazy — `MachO::symbols` | Pool via `strings::macho_symtab_string_pool` |
| Dylib paths | Modeled | Lazy — `linked_dylibs` | |
| Section `relocation_info` | Modeled | Lazy — `relocations` | |
| Export trie / bind opcodes | Modeled | Lazy — `exports`, `bind_opcodes` | |
| Structural LC / section edits | Partial | `insert_load_command_at`, `remove_load_command`, `add_section` | |
| FAT unpack / `from_fat_index` | Modeled | Eager first arch / index select | |
| FAT build / merge / thin slice | Modeled | `FatHeader::build`, `merge`, `slice_ref` | |
| Thin 64-bit construction | Scoped (`macho,write`) | `build::MachOBuilder` | macOS 13+ x86-64/arm64 executables/dylibs, checked fixups, imports/ASCII exports, chained bindings/rebases, dependencies/RPATHs; unsigned output with external signing |
| Chained fixups | Modeled | Lazy — `chained_fixups`, `chained_fixup_slots`, `decode_chained_fixups`, `decode_chained_pointer_as` | All import formats and `DYLD_CHAINED_PTR_*` formats 1–14 (arm64e auth/bind, 32-bit, kernel/shared cache, segmented), multi-start pages, bounded name/page expansion; zlib symbol pools unsupported; edits only re-validate PTR64_OFFSET chains; authenticated arm64e writer excluded |
| `LC_UNIXTHREAD` entry PC | Modeled | Lazy — `UnixThreadCommand::program_counter` | x86/x86-64/ARM/arm64/PPC thread-state flavors, including unified headers |
| Lifecycle / TLV / unwind generation | Scoped (`macho,write`) | `add_initializers`, `add_terminators`, `add_thread_local`, `add_unwind` | Ordered initializer arrays, generated libSystem `__cxa_atexit` termination registration, one initialized Apple TLV template/descriptor, caller-encoded EH frame; no compact-unwind synthesis |
| Custom-data editing | Scoped (`macho,write`) | `edit::MachOEdit`, `edit_fat_slice`, `rebuild_fat_slice` | Replace/grow/add checked custom data, bounded dylib/RPATH names, explicit signature stripping/external re-signing, selected FAT slice rebuilding; mapped VAs and unselected slice bytes preserved |
| Embedded signature containers | Scoped | `code_signature`, `code_signature_data`; `reserve_code_signature`, `write_code_signature`, `remove_code_signature` with `macho,write` | Read opaque command/blob; reserve final metadata before hashing; fixed-size installation; thin LE x86-64/arm64 final __LINKEDIT only; no cryptography |

## Cross-format (core crate)

| Area | Module | Notes |
|------|--------|-------|
| CString / name helpers | `strings` | PE imports/exports/sections, Mach-O pools |
| VA / file offset | `validation` | Per-format translators |
| Overlap detection | `validation` | Section/segment file ranges |
| Consistency checks | `validation` | Non-fatal `ValidationIssue` list |
| Reloc listing by VA/offset | `reloc` | Thin wrappers per format |
| Layout planner (dry-run) | `write` | `plan_pe_insert_section`, `WriteMode` |

## Iterator / view policy

| API | Strategy |
|-----|----------|
| `PE::section_data`, `ELF::section_data` | Zero-copy `&[u8]` views into `buffer` |
| `PE::imports`, `PE::exports`, ELF/Mach-O symbol tables | Lazy parse; allocates `Vec` of entries |
| `PE::base_relocations()` | On demand; collects blocks and entries |
| `reloc::pe_parse_base_relocations` | Delegates to lazy `PE::base_relocations()` |
| `PE::imports_iter`, `exports_iter`, `export_functions_iter` | Streaming entries and borrowed names; imports allocate only for lossy UTF-8 |
| `PE::base_relocations_iter`, `debug_iter` | Streaming records without allocation |
| `PE::rva_index` | Optional allocated index; immutable borrows, overlap fallback |
| `ElfHeaders::program`, `section` | Direct entry parsing without allocation |
| `MachHeaders::commands` | O(n) command traversal without allocation |
| `FatHeaders::arch`, `slice` | Selected FAT metadata and bytes without allocation |
| `ELF::section_name_ref`, `SymbolTable::name_ref`, `MachO::linked_dylibs_iter` | Borrow valid UTF-8, allocate only for lossy decoding |

[`Field`]: https://docs.rs/hexspell/latest/hexspell/field/struct.Field.html

All three format types support borrowed file buffers through `from_slice`, with the same eager header/table parsing and lazy payload parsers as owned inputs. Mach-O FAT selection borrows the selected thin image.

Header-only views: `elf::view::ElfHeaders` models the ELF file header with individual program/section entries on demand, including extended counts. `macho::view::MachHeaders` models a thin Mach-O file header with load-command headers on demand. Neither eagerly validates payloads.
