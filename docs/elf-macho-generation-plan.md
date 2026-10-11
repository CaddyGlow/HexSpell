# ELF and Mach-O creation and editing plan

Status: scoped ELF and Mach-O construction, dynamic linking, runtime metadata and
transactional editing milestones are implemented. The
[validation matrix](elf-macho-generation-validation.md) records the supported
profiles and separate native acceptance evidence. The limits below remain explicit:
this work does not promise a general linker, arbitrary executable relayout,
compact-unwind synthesis or additional CPU/TLS/signature profiles.

Extend the approach in [PE generation](pe-generation-plan.md) to ELF and Mach-O:
construct images from owned specifications, resolve symbols and fixups, return
ordinary parsed format objects, and edit existing images transactionally. Deliver
small, usable milestones with independent structural and native runtime checks.

## Existing foundation

| Capability | PE reference | ELF today | Mach-O today |
| --- | --- | --- | --- |
| Creation | `PeBuilder`, `build`, `build_with_layout` under `pe,write` | `ElfBuilder` Linux AMD64; explicit-layout ELF32/64 serializer in either byte order | `MachOBuilder` x86-64/arm64 executable/dylib profiles |
| Layout edits | Section insertion/removal/rename and layout helpers | `insert_section`, `insert_pt_load`, split/merge load segments | Load-command insertion/removal, `add_section`, `insert_segment` |
| Symbols and linkage | Builder imports, exports, fixups and base relocations | Symbols, versioned imports/exports, visibility, eager slots, RELA | Imports/ASCII exports, chained PTR64_OFFSET binding/rebasing |
| Runtime metadata | TLS and caller-supplied x64 unwind data | Shared lifecycle arrays, general-dynamic TLS, caller CIE/FDE and EH-frame index | Initializer arrays, runtime-registered terminators, one initialized Apple TLV template, caller EH-frame |
| Owned payload editing | Resource serialization and transactional replacement | Transactional custom data/owned notes/bounded loader strings | Transactional custom data/command strings/signature stripping/FAT replacement |
| Containers | Ordinary PE image | Archive reader | Existing FAT build, merge and slice APIs |

Reuse `Field`, `FixedBytes`, `ByteOrder`, `FileParseError`, validation helpers and
the existing readers. Existing insertion routines are implementation candidates,
not proof that arbitrary executable relayout is safe. In particular, ELF insertion
can modify tables before later fallible work; new transactional APIs must isolate
all mutations in a candidate image.

ELF notes and custom sections, and Mach-O custom sections, provide embedded-data
use cases. They do not acquire PE resource IDs, languages or codecs. macOS bundle
resources remain outside the binary writer's scope.

## Scope and delivery targets

The first useful release should create and run a Linux x86-64 executable, create
and load a Linux shared object, create and run macOS x86-64 and arm64 executables,
and create and load matching dylibs. It should also safely edit supported metadata
and embedded payloads in existing images. Complete the Linux path first, then
the macOS path; editing has separate acceptance gates from generation.

| Area | Initial delivery | Later extension |
| --- | --- | --- |
| ELF execution | Linux x86-64 little endian; fixed-address executable, then dynamic PIE and shared object | Linux AArch64 and i386, other OS ABI profiles |
| ELF layouts | Checked class/endian-aware serialization; ELF32 and big-endian synthetic tests | Runtime support only after target-specific fixup and loader tests |
| Mach-O execution | Thin 64-bit little-endian x86-64 and arm64; explicit macOS deployment target | Other Apple platforms and arm64e |
| Mach-O layouts | New writer supports the selected 64-bit profiles; preserve existing 32-bit/BE parsing | 32-bit/BE creation as a separate structural milestone |
| Containers | Reuse FAT writer to package independently validated thin images | Archive creation and generalized container editing |
| Linker scope | Caller-provided machine code, named symbols, explicit supported fixups | Object-file linking, relaxation and arbitrary binary rewriting |

Reject unsupported target/class/endianness combinations explicitly. A generic
serializer passing a round-trip test does not establish an executable ABI profile.
Object creation (`ET_REL`, `MH_OBJECT`) is a later feature, with its own relocation
and linker acceptance tests; it is not required to reach the PE executable/DLL scope.

## API and compatibility contracts

1. Add opt-in `write = []`, combined with independently selected `pe`, `elf`,
   and `macho` features. Keep default
   features, existing patch APIs, Rust 1.88, `no_std + alloc`, and zero runtime
   dependencies. External inspection/signing programs belong in validation scripts.
2. Propose `elf::build::ElfBuilder` and `macho::build::MachOBuilder`, each with
   `build(&self)` and `build_with_layout(&self)`. Return `ELF` or `MachO` and an
   optional layout report. Failed builds leave specifications reusable.
3. Give each format its own target, image-kind, segment, section and linkage
   specifications. Segments and sections are distinct identities. Resolve placement
   with measure → place → resolve → emit → reparse stages.
4. Use opaque builder-owned section/segment/symbol/import handles. Match PE's
   foreign-handle rejection and deterministic output. If using its `Rc` token
   pattern, document the same `!Send`/`!Sync` consequence. Do not derive ambiguous
   builder cloning. Ownership tokens never affect output bytes.
5. Specifications have no invented `Field` offsets. Only emitted and reparsed
   structures expose actual offsets. Reports distinguish file offsets, preferred
   virtual addresses, image-relative addresses and virtual-only locations.
6. Separate build-time fixups from runtime relocations/bindings. Specify encoding,
   addend, origin, width and target for each supported architecture. Reject overflow,
   overlapping writes, invalid handles, and writes into zero-fill storage.
7. Keep headers/sections eager and large tables lazy. Add reader coverage required
   to validate emitted formats before relying on it in a serializer test.
8. Reuse existing errors; semver-review additions to exhaustive public enums.
   New editing APIs return an edit report listing moved ranges, changed metadata,
   preserved addresses and signature/build-ID consequences.

Share only demonstrably identical private arithmetic and bounded-write helpers.
Keep placement, imports and runtime relocations format-specific; avoid refactoring
the working PE builder as a prerequisite.

## Implementation milestones

| Unit | Work and exit criteria | Depends on |
| --- | --- | --- |
| C0 | Target matrix, API sketches, deterministic defaults, handle/error contracts, synthetic fixture helpers and baseline checks | None |
| E1 | ELF headers, segment/section placement, string table, zero-fill, entry point and layout report; static Linux x86-64 hello/exit example runs | C0 |
| E2 | Static symbols and checked build-time fixups; independent reader agrees on addresses and bytes; failure tests cover overflow and foreign handles | E1 |
| E3 | Dynamic strings/symbols, hashes, needed libraries, SONAME/RUNPATH, relative and symbol relocations, import slots, PIE/shared-object output; executable calls an import and host loads/calls an export | E2 |
| E4 | Transactional ELF edits for nonallocated data and supported dynamic strings; preserve existing code/data VAs; growth and rejection tests plus native reruns | E1, E3 for dynamic edits |
| E5 | Initializers/finalizers, scoped TLS model and caller-provided unwind integration; constructor ordering and per-thread storage verified | E3 |
| M1 | Mach-O thin builder, segments/sections, load commands, zero-fill, symbols, entry and layout report; structural x86-64/arm64 checks | C0 |
| M2 | Target fixups, imports, exports, link-edit layout, runtime binding/rebasing and dylib metadata; independent inspection for both targets | M1 |
| M3 | Signing workflow and macOS acceptance: hello executable, dylib loader, imported call and relocated pointer tests pass on each target | M2 |
| M4 | Transactional custom-section and supported dylib/RPATH edits, explicit signature handling, FAT replacement; edited images pass structural and native checks | M3 |
| M5 | Initializers/terminators, scoped thread-local variables and caller-provided unwind integration; thread and unwind acceptance tests | M3 |
| C1 | Examples, feature/MSRV checks, documentation, fuzz coverage and validation report for delivered matrix | Delivered E/M units |

Recommended order: C0, E1–E4, M1–M4, then E5/M5 and C1. Record validation evidence
per milestone. A release may deliver fewer milestones with an explicit coverage
matrix; TLS and unwind remain partial until E5/M5 pass.

## ELF construction details

E1 must place program headers independently of section headers, support images
without a section table, and separate allocated sections from file-only metadata.
Validate load-segment ordering, alignment congruence, `p_filesz <= p_memsz`, mapped
header extents and `SHT_NOBITS` without artificial file payloads. These constraints
follow the [ELF program-loading specification](https://gabi.xinuos.com/elf/07-pheader.html).

Reserve header capacity before placement. Exercise null sections, `.shstrtab`,
extended count encodings and class-width overflow with bounded synthetic tests.
Reject executable entry points outside initialized executable bytes. Define
explicit segment permissions and avoid writable executable segments by default.

E2 emits `.symtab`/`.strtab` with binding order, section indices and section-header
links set consistently. Fixups initially cover the x86-64 encodings needed by the
examples; no silent conversion of unsupported relocation types.

E3 starts with explicit interpreter paths and a documented Linux loader profile.
Emit coherent `PT_INTERP`, `PT_DYNAMIC`, dynamic tags, `.dynsym`/`.dynstr`, a supported
hash table, and RELA records. Use eagerly resolved GOT slots first; PLT stubs/lazy
binding are an explicit extension. Exports specify binding/visibility; dependency
libraries and symbol names remain separate. Add versioned-symbol support before
claiming compatibility with dependencies that require it. Unsupported IFUNC, copy
relocations, packed relocations and TLS models must be rejected or left outside
the advertised profile. Test loader discovery without section headers; extend
readers if their current section-based lookup cannot validate this output.

E5 selects one documented TLS model first and tests multiple threads. Initializer
arrays require correct pointer relocations. Unwind data may be caller-supplied,
but pointer encodings and registration must still be validated. Pin the relevant
processor ABI references in the implementation review before adding encoders.

## Mach-O construction details

M1 reserves load-command space before laying out payloads, updates `ncmds` and
`sizeofcmds`, checks command alignment and fixed-width names, and separates
segment file sizes from virtual zero-fill. Make page alignment and deployment
target explicit target-profile settings. Model entry semantics and required
platform/dyld commands using Apple's [load-command definitions](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/EXTERNAL_HEADERS/mach-o/loader.h).

M2 builds symbols/string pools, export data, import metadata, indirect-symbol
tables where used, and `__LINKEDIT` in one measured layout. Preserve stable dylib
ordinals and distinguish install name, dependencies and RPATHs. Cover x86-64
relative addressing and arm64 branch/page-address encodings with signed-range
and alignment tests; reject requests that would require unsupported veneers.

The delivered macOS 13+ x86-64/arm64 profile uses scoped modern
`DYLD_CHAINED_PTR_64_OFFSET` fixups for new images,
using Apple's [chained-fixup definitions](https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/include/mach-o/fixup-chains.h),
and add missing readers first. Legacy bind/rebase opcode emission is a distinct
compatibility extension. Do not accept arm64e authenticated pointer formats under
the ordinary arm64 profile. Inspect output against linker-generated reference
images for the same deployment target.

M3 initially uses external ad-hoc signing in the macOS acceptance harness after
emission. The library reports unsigned output; native SHA/signature generation,
developer signing and notarization are separate work. Validate any signature
command/layout changes introduced by the signing tool by reparsing the result.
The runnable example workflow must include the signing step required by its
tested platform. Never equate successful Linux parsing with macOS acceptance.

M5 explicitly scopes thread-local descriptor and initializer conventions. General
compact-unwind/DWARF synthesis remains outside the first writer; test supported
caller-provided unwind data on macOS before advertising it.

## Transactional editing

Propose separate `elf::edit` and `macho::edit` sessions over an owned source image.
Plan all operations against one source snapshot, validate a candidate, then swap
it into the caller's object only on success. Reparse after commit so all cached
header fields have current offsets. Failed edits preserve the original bytes and
parsed state; borrowed images require an explicit owned copy for resizing.

The initial supported operations are:

- ELF: rename sections, replace/add/remove unreferenced nonallocated custom data,
  update owned notes, and replace interpreter/NEEDED/SONAME/RUNPATH strings within
  validated capacity. Grow dynamic strings only when a proven mapping plan updates
  every known consumer; otherwise return an unsupported-operation error.
- Mach-O: replace payloads within validated section capacity; edit dylib install
  names, dependencies and RPATHs within reserved command space; add custom data
  only where a checked placement preserves existing mapped addresses. Size-changing
  `__LINKEDIT` operations require a complete supported offset inventory.
- FAT: edit a selected thin slice, then rebuild container offsets/alignment using
  the existing FAT writer. Preserve all other slice bytes and architecture metadata.

For each edit, inventory every affected file offset, VA, section/symbol index and
table size. Reject removal of referenced sections unless every reference has a
supported rewrite. Preserve opaque data and unknown commands byte-for-byte when
their locations stay unchanged; reject movement when hidden references cannot be
ruled out. Do not scan arbitrary code for pointers or promise general compaction.

Mach-O signature policy defaults to rejecting changes to signed images. An explicit
strip-and-re-sign workflow removes supported signature metadata transactionally
and reports that external signing is required. Preserve unknown signature layouts
by refusing the edit. ELF build IDs get an explicit preserve-as-stale, remove, or
supported-regenerate policy; never imply that an old ID describes modified bytes.

## Suggested files

Create modules only when their milestones land:

```text
src/elf/build/{mod,layout,emit,symbols,fixup,dynamic}.rs
src/elf/edit.rs
src/macho/build/{mod,layout,emit,symbols,fixup,dyld}.rs
src/macho/edit.rs
tests/{elf_build,elf_edit,macho_build,macho_edit}.rs
tests/support/                         synthetic inputs and independent expected bytes
examples/{elf_hello,elf_shared,macho_hello,macho_dylib}.rs
tests/scripts/                        independent inspection and native loader harnesses
docs/elf-macho-generation-validation.md
```

Keep existing format modules as entry points. Add reader regressions to
`tests/elf.rs` and `tests/macho.rs`; generation and edit tests belong in the new
files. Record provenance and rebuild recipes for every committed binary fixture.

## Validation and completion

Each milestone needs exact-byte assertions independent of the production layout
planner, parse/build/edit round trips, deterministic repeated output, overflow and
truncation cases, and failure atomicity. Test zero-length payloads, zero-fill,
alignment boundaries, table growth, stale/foreign handles, stripped inputs and
unsupported metadata. Every bugfix begins with a failing regression.

Use `readelf`/`llvm-readobj` for ELF and LLVM tools plus native `otool`/`dyld_info`
for Mach-O. Record tool versions and deployment profiles. Native tests execute
generated programs, load shared libraries, call exports, resolve imported calls,
check initialized and zero-fill data, and verify runtime relocations across load
addresses. Add initializer/TLS/unwind checks as their milestones land. Re-run the
same behavior after supported edits and after extracting rebuilt FAT slices.

Linux x86-64 runtime acceptance and native macOS x86-64/arm64 acceptance are
separate gates. If a runner is unavailable, mark its target structurally validated
only and leave the native milestone incomplete. Keep external tools and platform
SDKs out of ordinary dependency-free library tests.

Finish each implementation unit with `cargo fmt`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test`. Also run clippy/tests
with the `write` feature enabled, per-format `--no-default-features` checks,
`no_std + alloc` checks, existing `pe,write` regressions and Rust 1.88 checks.
Extend malformed-input/round-trip fuzzing to builders and edit plans with bounded
allocation sizes.

Update the guide, coverage matrix, relevant layout tables, README and changelog
when behavior ships. Label structural, runtime and unsupported coverage separately.
Completion means usable documented examples, passing applicable acceptance gates,
and a recorded validation report—not merely successful reparsing of output.
