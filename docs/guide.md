# HexSpell

HexSpell is a dependency-free Rust library for parsing and patching **PE**, **ELF**, and **Mach-O**
binaries. The API mirrors the on-disk layout: every exposed header field is a [`Field`] with the
real `offset` and `size` in the file buffer.

## Design principles

1. **1:1 with the file format** — fields live where the specification places them (`ei_data` in the
   ELF header, `machine` in the COFF header, segment names as raw bytes, and so on).
2. **Explicit buffer** — `PE`, `ELF`, and `MachO` own a `buffer: Vec<u8>`. Patching always passes
   that buffer into `Field::update` or layout accessors.
3. **Small utility surface** — helpers such as `insert_section` perform real structural edits; they
   do not hide the underlying tables.

## Core types

| Type | Role |
|------|------|
| [`Field`] | Value + absolute offset + on-disk size |
| [`FixedBytes`] | Fixed-size byte array (section names, `e_ident`, Mach-O `segname`) |
| [`ByteOrder`] | ELF / Mach-O endianness helpers |
| [`FileParseError`] | Shared parse and patch errors |

See [docs/layout.md](layout.md) for `field()` / `field_mut()` accessors on program headers,
section headers, and segments.

## PE (Windows)

PE32 and PE32+ images can also be built from scratch with `pe::build::PeBuilder`.
The [generation design](pe-generation.md) and [implementation plan](pe-generation-plan.md)
describe the scope and validation gates. See [PE generation and resource editing](#pe-generation-and-resource-editing)
below for the implemented API.

PE files are modeled as:

```
dos_header → coff_header → optional_header → sections[]
```

```rust
use hexspell::pe::PE;

let pe = PE::from_file("app.exe")?;
println!("arch: {}", pe.architecture());
println!("entry: {:#x}", pe.optional_header.entry_point.value);

pe.optional_header
    .entry_point
    .update(&mut pe.buffer, 0x1000)?;

pe.write_file("app-patched.exe")?;
```

Imports, exports, TLS, exceptions, symbols, and other data directories are available via lazy parsers on [`PE`] (for example [`PE::imports`], [`PE::exports`], [`PE::tls`], [`PE::coff_symbols`]). To change the load address and patch base relocations in the buffer, use [`PE::apply_image_base`].

Insert a section:

```rust
use hexspell::pe::{PE, section::{NewSection, CODE, READ, EXECUTE}};

let mut pe = PE::from_file("app.exe")?;
pe.insert_section(NewSection {
    name: ".data".into(),
    data: vec![0x90; 64],
    characteristics: CODE | READ | EXECUTE,
})?;
pe.write_file("app-section.exe")?;
```

Section insertion preserves trailing overlays. File shifts rebase section raw
data, COFF symbol/relocation/line-number pointers, the certificate directory,
and debug raw-data pointers. Optional-header growth keeps raw sections aligned
to `FileAlignment`. Section removal compacts the section table without shifting
the remaining file data by a section-header width. These helpers do not rebuild
arbitrary references embedded in machine code or directory payloads when a
middle section's RVA is removed.

The optional [pefile verification suite](../tests/scripts/README.md) compares
field values, offsets, and widths and checks serialized images after edits.
The [PE benchmark tool](../tools/pe-bench/README.md) provides a reproducible
corpus and separate parsing scopes for HexSpell, Goblin, object, and pefile.

### Reconstructing a PE memory image

Enable `pe-reconstruct` alongside `pe`. This independent opt-in feature adds no
dependencies, does not require `write`, and works with `no_std + alloc`:

```toml
caddy-hexspell = { version = "1.2.2", default-features = false, features = ["pe", "pe-reconstruct"] }
```

Supply a contiguous snapshot starting at the image base: input offset `rva`
contains bytes from `image_base + rva`. Headers must be present and parseable.
With `std` enabled, a dump can be converted and saved as follows:

```rust
use hexspell::pe::PE;

let memory = std::fs::read("mapped-image.bin")?;
let reconstructed = PE::from_memory_image(&memory)?;
reconstructed.write_file("reconstructed.exe")?;
```

The function copies each section from its RVA into newly packed, file-aligned
storage in section-table order, preserving section RVAs, entry point, and
ImageBase. It captures `VirtualSize` bytes, falling back to `SizeOfRawData` when
`VirtualSize` is zero. It materializes virtual tails and `.bss` contents, including
runtime modifications, changes materialized uninitialized-data sections to
initialized data, and zero-pads output raw sizes to `FileAlignment`. Header/image
sizes, code/data totals, section raw offsets/sizes, and checksum are recomputed.
The input slice remains unchanged and the returned `PE` has ordinary file offsets
in its `Field` values.

File-only data cannot be recovered from a memory snapshot: overlays, original
file padding, certificates, COFF symbols, section relocations/line numbers, and
file-only debug payload references are omitted or cleared. Mapped debug payload
pointers are rebuilt from their RVAs; malformed or partly captured debug records
are rejected. Debug directories embedded in headers are rejected to prevent
rewriting header fields. Other directory RVAs remain unchanged and their payloads
are not eagerly validated.

All required section bytes must be present; missing pages are errors, not
implicitly zero-filled. Truncated headers, overlapping section ranges, arithmetic
overflow, and invalid alignments return `FileParseError`. This initial API supports
power-of-two `SectionAlignment >= 4096` and power-of-two `FileAlignment` from
512 through 65536, with `FileAlignment <= SectionAlignment`.

This converts the layout described by the [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
It does not reverse loader relocations, restore overwritten import thunks, infer
the actual load base, or repair missing headers. A captured live process image may
need additional work before it can execute again.

## ELF (Linux)

ELF endianness is stored in `header.ei_data`. Use [`ELF::byte_order`] as a convenience alias.

```rust
use hexspell::elf::ELF;

let mut elf = ELF::from_file("./a.out")?;
let order = elf.byte_order()?;

elf.header
    .entry
    .update_with(&mut elf.buffer, 0x2000, order)?;

println!("phdr count: {}", elf.header.ph_num.value);
elf.write_file("a.out.patched")?;
```

Read a program header offset without mutating the container:

```rust
let offset = elf.program_headers[0].p_offset();
```

Patch it:

```rust
elf.program_headers[0]
    .p_offset_mut()
    .update_with(&mut elf.buffer, 0x4000, order)?;
```

## Mach-O (macOS)

Mach-O has no endianness byte in the header; byte order is derived from the `magic` bytes on disk.

```rust
use hexspell::macho::MachO;

let macho = MachO::from_file("binary")?;
println!("byte order: {:?}", macho.byte_order());
println!("first segment: {}", macho.segments[0].name());
```

FAT binaries are unpacked automatically; the parsed object refers to the embedded thin Mach-O.

### Chained fixups and legacy entry points

`MachO::chained_fixups` decodes `LC_DYLD_CHAINED_FIXUPS` metadata: all three
import encodings and every `DYLD_CHAINED_PTR_*` format in Apple's
`fixup-chains.h`, including arm64e authenticated pointers and multi-start pages.
`MachO::chained_fixup_slots` walks the chains in the file buffer and returns one
`ChainedFixupSlot` per pointer, with the raw word as a `Field` (real offset and
4- or 8-byte width) and the decoded `ChainedPointer`. Authenticated slots carry
their signing schema (key, diversity, address diversity); the PAC value itself
is computed by dyld at load time and is not stored in the file.

```rust
use hexspell::macho::{dyld::ChainedPointer, MachO};

let macho = MachO::from_fat_index("binary", 1)?;
let base = macho.segments.iter().find(|s| s.fileoff() == 0 && s.filesize() > 0).unwrap().vmaddr();
for slot in macho.chained_fixup_slots()?.unwrap_or_default() {
    if let ChainedPointer::AuthRebase { auth, .. } = &slot.pointer {
        println!(
            "{:#x} -> {:#x?} key {:?} discriminator {:#x}",
            base + slot.vm_offset,
            slot.rebase_vmaddr(base),
            auth.key,
            auth.discriminator(base + slot.vm_offset),
        );
    }
}
```

`UnixThreadCommand::program_counter` locates the entry PC (`eip`/`rip`, `pc`,
`srr0`) in an `LC_UNIXTHREAD` register state for x86, x86-64, ARM, arm64 and
PowerPC, returning a patchable `Field`.

## Cross-format helpers

| Module | Role |
|--------|------|
| [`strings`] | PE import/export/section names; Mach-O cstring pools |
| [`validation`] | File-range overlap detection, VA ↔ file offset, consistency checks |
| [`reloc`] | List relocations by RVA/VA or file offset (per-format wrappers) |
| [`write`] | Layout planner / dry-run flag for structural edits |

### Lazy vs eager parsing

- **Eager at `from_buffer`:** PE DOS/COFF/optional header, section table, and base relocation directory; ELF/Mach-O header tables and segments.
- **Lazy on demand:** PE imports/exports/TLS/resources, ELF `.dynamic`/symbols/relocations, Mach-O typed load commands and symbol tables.
- **Zero-copy views:** `PE::section_data`, `ELF::section_data` return slices into `buffer`.

See [coverage.md](coverage.md) for the full matrix.

## API overview (1.0)

HexSpell 1.0 is the first stable release. There are no prior public API versions to migrate from.
Breaking changes during 1.0 development are listed in [CHANGELOG.md](../CHANGELOG.md).
New code should use:

- `PE` / `ELF` / `MachO` container types with `buffer: Vec<u8>`
- `Field::update` / `update_with` for in-place patches
- Layout accessors (`p_offset()`, `seg.vmaddr_mut()`, …) documented in [layout.md](layout.md)

## Error handling

All parsers return [`Result`]. Typical variants:

- [`FileParseError::InvalidFileFormat`] — bad magic, unknown PE optional header magic, etc.
- [`FileParseError::BufferOverflow`] — truncated file or string longer than field size.
- [`FileParseError::ValueTooLarge`] — numeric value does not fit in the on-disk field width.

## Known limitations

Some edge cases remain partial (for example PE `remove_section` without full entry-point rebuild, or Mach-O load-command removal with code-signature padding). See [coverage.md](coverage.md) for the full matrix.

[`strings`]: crate::strings
[`validation`]: crate::validation
[`reloc`]: crate::reloc
[`write`]: crate::write

[`Field`]: crate::field::Field
[`FixedBytes`]: crate::field::FixedBytes
[`ByteOrder`]: crate::field::ByteOrder
[`FileParseError`]: crate::errors::FileParseError
[`Result`]: crate::errors::Result
[`ELF::byte_order`]: crate::elf::ELF::byte_order
[`PE`]: crate::pe::PE
[`PE::imports`]: crate::pe::PE::imports
[`PE::exports`]: crate::pe::PE::exports
[`PE::tls`]: crate::pe::PE::tls
[`PE::coff_symbols`]: crate::pe::PE::coff_symbols
[`PE::apply_image_base`]: crate::pe::PE::apply_image_base


## Borrowed parsing

Use `PE::from_slice(&bytes)`, `ELF::from_slice(&bytes)`, or
`MachO::from_slice(&bytes)` to inspect existing bytes without copying the file
buffer. These return `PE<&[u8]>`, `ELF<&[u8]>`, and `MachO<&[u8]>`;
headers and tables still allocate as before, and lazy parsers remain available.
The input must outlive the parsed image. FAT Mach-O input selects the first
architecture as a borrowed thin slice; field offsets are relative to that slice.
To select another architecture, pass `MachO::fat_slice_ref(&bytes, index)?`
to `MachO::from_slice`.

For editing, keep using `from_buffer(Vec<u8>)` or `from_file`. These retain
owned buffers and editing methods. To edit borrowed input, explicitly copy it
and parse the owned bytes:

```rust
# use hexspell::pe::PE;
# let bytes = include_bytes!("../tests/samples/sample1.exe");
let view = PE::from_slice(bytes)?;
let mut editable = PE::from_buffer(view.buffer.to_vec())?;
editable.coff_header.time_date_stamp.update(&mut editable.buffer, 0)?;
# Ok::<(), hexspell::errors::FileParseError>(())
```


## Header-only inspection

Use `elf::view::ElfHeaders::parse(&bytes)` or
`macho::view::MachHeaders::parse(&bytes)` when only the file header is needed.
Like `pe::view::PeHeaders`, these borrow the input and allocate nothing during
initial parsing. They accept complete headers even when referenced tables or
payloads are missing; successful header parsing does not validate the full file.

`ElfHeaders::program(index)` and `section(index)` parse one table entry on
demand without allocating. `program_count()` and
`section_count()` resolve extended counts through section zero when necessary.
`MachHeaders::command(index)` walks command sizes to read a load-command header
without allocation or payload parsing. Entry access checks file bounds and
retains the original field offsets and sizes.

Mach-O header views require thin input. For FAT files, select an architecture
with `MachO::fat_slice_ref(&bytes, index)?` before parsing the view; field offsets
are relative to that selected slice. FAT selection and thin header views do not
allocate.
Owned parsing and editing continue to use `from_buffer` or `from_file`.


## Streaming directory inspection

PE directory iterators inspect entries without collecting tables:

```rust
# use hexspell::pe::{PE, read::ImportEntryRef};
# let bytes = include_bytes!("../tests/samples/sample1.exe");
let pe = PE::from_slice(bytes)?;
for dll in pe.imports_iter()? {
    let dll = dll?;
    for entry in dll.entries {
        if let ImportEntryRef::ByName { name, .. } = entry? {
            println!("{}: {name}", dll.dll_name);
        }
    }
}
# Ok::<(), hexspell::errors::FileParseError>(())
```

- `imports_iter()` yields each descriptor once, a borrowed DLL name, and a thunk
  iterator. Names use `Cow<str>`: valid UTF-8 borrows the input; invalid UTF-8
  allocates its lossy decoding, matching `imports()`.
- `exports_iter()` yields named exports; `export_functions_iter()` yields every
  address-table slot, including ordinal-only entries and borrowed forwarders.
  Export strings retain strict UTF-8 validation.
- `base_relocations_iter()` yields borrowed blocks. Each block's `entries()`
  decodes relocation words without allocation. `to_owned()` explicitly collects
  one block.
- `debug_iter()` yields fixed-size debug records.

These iterators retain original `Field` offsets and sizes. PE directory iterators
and Mach-O command iterators return an error once and then stop. Fully traverse
them to validate every entry; stopping early validates only the visited portion.
Iterator construction may validate fixed table extents, but does not decode
unvisited names or payloads.

For repeated PE RVA lookup, `let index = pe.rva_index();` builds an optional index.
Use `index.rva_to_offset(rva)`, or pass `&index` to an import/export iterator's
`with_index` method. An index borrows the image so edits cannot invalidate it.
Overlapping section ranges use the original file-order lookup. Index construction
allocates; small section tables can be faster with the default linear mapper.

For ELF, `section_name_ref(index)` and `SymbolTable::name_ref(buffer, symbol)`
borrow valid UTF-8 names. For Mach-O, `MachHeaders::commands()` traverses all
command headers in O(n) without allocation, while repeated `command(index)`
calls rescan the prefix. `MachO::linked_dylibs_iter()` and
`LoadCommand::dylib_name_ref` borrow dylib paths. `FatHeaders::parse` and
`arch(index)` read FAT metadata without collecting an architecture vector.

Shared `strings::read_c_bytes`, `read_c_string_ref`,
`read_c_string_in_pool_ref`, and `CStringPool::resolve_ref` support borrowed
string inspection. Existing owned string helpers remain available.

## Migrating to 1.2.0

This release includes the following breaking API changes:

| Previous API | Replacement |
|---|---|
| `pe.base_relocations` field | `pe.base_relocations()?` to collect, or `pe.base_relocations_iter()?` to stream |
| `imports.descriptors` field | `imports.descriptors()` to borrow descriptors, or `imports.dlls[i].descriptor` |

PE parsing now validates headers and sections without reading the relocation
directory. Malformed relocation errors are reported on directory access or
`apply_image_base`. Relocation access reads current buffer bytes every time,
without a cache. `apply_image_base` still parses and applies relocations before
updating the preferred image base. To alter relocation fields, patch the buffer
through their `Field` values; there is no mutable cached relocation list.

Full parsers validate table extents and minimum entry sizes before reserving
capacity. Malformed ELF entry strides and Mach-O command/segment extents that
were previously accepted may now return errors.

Run `cargo bench --bench parsing` for dependency-free release measurements of
owned versus streaming directory inspection, names, command traversal, FAT
selection, and linear versus indexed RVA lookup. File I/O and setup are outside
timing; allocation counts include calls to allocate or reallocate, and byte counts
are total requested bytes rather than peak live memory.

## PE generation and resource editing

Enable the opt-in `write` feature with `pe` (disabled by default). It adds no dependencies
and works with `no_std` plus `alloc`; `std` is needed only for file APIs/examples:

```toml
[dependencies]
caddy-hexspell = { version = "1.2.2", features = ["pe", "write"] }
```

`pe::build` constructs x86 PE32 and x64 PE32+ images from owned section bytes,
without a template, linker, SDK, or runtime dependencies. Callers provide machine
code. This minimal x64 DLL entry returns `TRUE`:

```rust
use hexspell::pe::{
    build::{ImageKind, PeBuilder, SectionSpec, Target},
    section::{CODE, EXECUTE, READ},
};

let mut builder = PeBuilder::new(Target::X64, ImageKind::Dll);
let text = builder.add_section(SectionSpec::new(
    ".text", vec![0xb8, 1, 0, 0, 0, 0xc3], CODE | EXECUTE | READ,
))?;
let entry = builder.define_symbol(&text, 0)?;
builder.set_entry_point(&entry)?;
let (image, layout) = builder.build_with_layout()?;
assert_eq!(image.optional_header.entry_point.value, layout.symbol(&entry).unwrap().rva);
# Ok::<(), hexspell::errors::FileParseError>(())
```

The returned image is an ordinary owned `PE`; its `Field` offsets refer to actual
emitted bytes and existing patching APIs apply. `build()` returns only the image.
Repeated builds preserve the specification and emit deterministic bytes. Handles
belong to one builder; foreign handles fail. Builders/handles use `Rc` identity and
are not `Send` or `Sync`. Use independent builders for independent outputs.

`SectionSpec::virtual_size` may exceed the supplied bytes for zero-filled tails.
Symbols may denote virtual positions and exclusive ends, but entry points,
callbacks, exports, and fixup writes must refer to initialized executable or
writable bytes as appropriate. The layout report gives RVAs, VAs, file locations,
and import slots; virtual-only symbols and end markers have no file offset.

`add_import` and `add_import_ordinal` return stable IAT handles; exact duplicates
reuse a slot. `add_export` accepts an explicit ordinal and optional public name;
`set_export_base` controls sparse ordinal tables, and names are sorted on emission.
`add_fixup` supports RVA32, x86 VA32, x64 VA64, and signed Rel32 writes with explicit
section-relative origins and addends. Absolute VA writes generate base relocations.
`set_tls` registers a template, four writable index bytes, and ordered callbacks.
`add_runtime_function` registers x64 ranges and caller-supplied unwind bytes.

Header options currently expose image base, subsystem, and file/section alignments.
Conventional alignments are supported; low-alignment images are rejected. Generated
table names (`.idata`, `.edata`, `.reloc`, `.tlsdir`, `.pdata`, `.rsrc`) are reserved.
Unwind bytes are caller-reviewed opaque data; this API does not encode arbitrary
compiler unwind programs. Forwarders and data exports are not supported by the builder.

Resources have two representations. `ResourceTree` remains the lazy on-disk view.
`ResourceDirectoryOwned` (also `OwnedResources`) owns editable metadata, raw UTF-16
keys, and payload bytes. `owned_resources()` imports the complete tree and checks
metadata and payload extents, including payloads in another section. `get`, `insert`,
`replace`, `remove`, and `rename` operate on generic paths. Insert requires existing
parent directories; `entries` permits explicit enumeration and tree construction.
Duplicate keys require replacement. Unknown payloads and unpaired surrogates survive
import and emission; canonical ordering and padding can change.

```rust
use hexspell::pe::resource::SignaturePolicy;
# let mut image = hexspell::pe::PE::from_buffer(include_bytes!("../tests/samples/sample1.exe").to_vec())?;
let mut resources = image.owned_resources()?;
resources.set_string(42, 0x0409, "Hello".encode_utf16().collect::<Vec<_>>())?;
let report = image.replace_resources(&resources, SignaturePolicy::PreserveBytes)?;
assert_eq!(image.owned_resources()?.string(42, 0x0409)?, Some("Hello".encode_utf16().collect()));
# let _ = report;
# Ok::<(), hexspell::errors::FileParseError>(())
```

`replace_resources` edits a candidate and commits only after validation, preserving
existing section RVAs. It appends a new resource section even for smaller replacements;
old resource bytes remain unreachable. It rejects overlapping/unsupported layouts.
Overlays and tracked debug/COFF/certificate file pointers move with inserted bytes.
Every successful edit recomputes summaries/checksum. `SignaturePolicy::PreserveBytes`
keeps certificate bytes and reports `Invalidated`; `Strip` removes a verified
certificate range and clears its directory. Unsigned inputs report `Unsigned`.
No signature is generated, and ambiguous certificate aliases are rejected.

Typed helpers include checked UTF-8 `Manifest` access, sixteen-slot `StringTable`
blocks, language-aware `set_string`/`string`, nested `VersionBlock` parsing/emission,
and ICO `Icon` parsing/emission with coordinated `set_icon`/`icon` tree operations.
Version unknown keys/values/children survive semantically; original padding does not.
Icon replacement allocates unused IDs and retains old image payloads that might be
shared. Cursor, menu, dialog, and bitmap resources remain opaque payloads.

Generate complete GUI executables and callable DLLs on Linux:

```sh
cargo run --features pe,write --example pe_hello -- x86 hello-x86.exe
cargo run --features pe,write --example pe_hello -- x64 hello-x64.exe
cargo run --features pe,write --example pe_dll -- x86 demo-x86.dll
cargo run --features pe,write --example pe_dll -- x64 demo-x64.dll
cargo run --features pe,write --example pe_resources -- hello-x64.exe edited-x64.exe preserve
```

On Windows, run `pe_dll_load` built for the DLL's architecture with its absolute
path; append `--force-relocation` to reserve the preferred base before loading.
The Hello examples exercise TLS-before-entry, dereferenced relocated pointers,
imports, manifests, RCDATA, strings, versions, icons, and x64 unwind metadata.
See [validation scripts](../tests/scripts/README.md) for independent inspection
and Windows runtime checks, including negative controls and forced relocation.

## Features and migrating to 1.2.2

| Feature | Default | Surface |
| --- | --- | --- |
| `std` | Yes | Filesystem I/O and standard-library error conversions |
| `pe` | Yes | PE parsing and existing section/layout editing |
| `elf` | Yes | ELF parsing and editing |
| `macho` | Yes | Mach-O parsing and editing |
| `common` | Yes | Public `reloc`, `strings`, `validation`, and `write` helpers; format-specific helpers follow enabled formats |
| `write` | No | Construction and transactional editing for enabled formats; does not enable `pe`, `elf`, or `macho` itself |
| `pe-reconstruct` | No | `PE::from_memory_image` with `pe`; memory-to-file layout conversion, independent of `write` and `std`; does not enable `pe` itself |

Core `field`, `errors`, and `utils` remain available in every configuration. Parsers
retain the private string-reading machinery they need when `common` is disabled.
`common` itself does not enable any format; generic helpers work by themselves.

**Breaking:** `default-features = false` now disables formats and the common helper
interface as well as `std`. To preserve the previous no-std surface, explicitly
enable `features = ["pe", "elf", "macho", "common"]`. Default users keep all
existing formats and helpers. Examples of narrower configurations:

```toml
# PE parser only, no standard library or public common helper interface.
caddy-hexspell = { version = "1.2.2", default-features = false, features = ["pe"] }
# In-memory PE generation and resource editing only.
caddy-hexspell = { version = "1.2.2", default-features = false, features = ["pe", "write"] }
# Shared fields plus generic helpers, with no format parser.
caddy-hexspell = { version = "1.2.2", default-features = false, features = ["common"] }
```

Choose one dependency declaration. Feature unification is additive: another
dependency may enable additional formats for the same package in the build graph.

## ELF and Mach-O generation and transactional editing

Enable `write` together with `elf` or `macho` to construct images from owned specifications.
The `write` feature does not enable parsers and adds no runtime dependencies. Both writers work with `no_std + alloc`. Builder handles contain
`Rc` ownership tokens, so builders and handles are neither `Send` nor `Sync`.
Foreign handles are rejected. Builders are reusable after failed builds and do
not implement ambiguous cloning.

`elf::build::ElfBuilder` targets Linux AMD64 ELF64 little-endian images.
Segments have explicit permissions; allocated sections belong to segments,
while `add_section(None, ...)` creates file-only metadata. The writer reserves
program headers before placement, emits a nonexecutable stack, separates zero-fill
from file data, and optionally omits section headers. Named static symbols and
checked `Absolute64`, `Absolute32` and `PcRelative32` fixups resolve before output.
PC-relative fields use the address immediately after the four-byte field as origin.

For explicit structural layouts, `elf::build::layout::serialize_layout` accepts
`HeaderSpec`, caller-positioned payload bytes, `ProgramSpec` and
`SectionHeaderSpec` slices. It supports ELF32/64 and either byte order, checks
class-width conversions and emits extended program/section counts and string-table
indices through section-zero escape encodings. It does not establish a runnable
CPU ABI, synthesize linkage or relocate caller payloads; use `ElfBuilder` for the
native Linux AMD64 profile.

Select `ImageKind::Pie` or `ImageKind::SharedObject` with `set_image_kind` for the
scoped Linux dynamic loader profile. PIE requires `set_interpreter` with an
explicit loader path. Global and weak symbols become dynamic exports;
`add_import_slot(library, name)` returns the symbol for an eagerly resolved GOT
slot, which caller-provided code addresses explicitly. `set_soname` and
`set_runpath` add owned dynamic strings. SysV hash tables and RELA records support
GLOB_DAT imports and writable Absolute64 pointer relocations. Default-visibility
global/weak pointer targets retain symbol preemption through `R_X86_64_64`; local,
hidden and protected targets use relative relocations. Absolute32 fixups
and read-only runtime relocation targets are rejected in dynamic images.
`add_versioned_import_slot` records dependency symbol versions, while
`set_symbol_version` assigns default export versions and `set_symbol_visibility`
sets ELF visibility. PLT stubs, lazy binding, IFUNC, copy and packed relocations
remain outside this profile.

Generated lifecycle pointers follow the same binding rules: default-visible global
and weak callbacks remain preemptible; local, hidden and protected callbacks use
relative relocations.

Shared objects support ordered `add_initializer` and reverse-order
`add_finalizer` arrays. PIE lifecycle arrays are rejected because a caller-provided
CRT must drive them. `add_tls_template` and `add_tls_address_slot` implement Linux
AMD64 general-dynamic TLS through `__tls_get_addr`; each thread owns its template
copy. `add_eh_frame` accepts a scoped version-1 `zR` CIE and caller-provided FDE/CFI
records, patches PC-relative function pointers and emits `PT_GNU_EH_FRAME`.
Personality functions, LSDA, exception-handler synthesis and other TLS models
are unsupported. See `elf_shared` and the native loader for complete examples.

```rust
# #[cfg(all(feature = "elf", feature = "write"))] {
use hexspell::elf::build::{Binding, ElfBuilder, SectionSpec, SegmentSpec, Target};
let mut builder = ElfBuilder::new(Target::LinuxX86_64);
let text = builder.add_segment(SegmentSpec::RX)?;
let section = builder.add_section(Some(&text), SectionSpec::new(".text",
    vec![0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]))?;
let entry = builder.define_symbol("_start", &section, 0, 9, Binding::Global)?;
builder.set_entry(&entry)?;
let (elf, layout) = builder.build_with_layout()?;
assert_eq!(elf.header.entry.value, layout.entry);
# }
# Ok::<(), hexspell::errors::FileParseError>(())
```

`macho::build::MachOBuilder` produces unsigned thin 64-bit little-endian images
for `Target::X86_64` or `Target::Arm64`, with an explicit macOS `Version`.
`enable_dyld` selects the macOS 13+ runtime profile; it requires a first `__TEXT`
segment with read/execute permissions and an executable entry or dylib install
name. `new_dylib` creates an `MH_DYLIB` specification. `add_dependency` assigns
stable one-based dylib ordinals; `add_rpath` emits search paths and `add_import`
binds an initialized, writable, eight-byte-aligned slot to a dependency symbol.
Defined symbols become exports through an ASCII radix trie. The writer emits
link-edit tables, deterministic UUIDs and modern `DYLD_CHAINED_PTR_64_OFFSET`
chained fixups. Writable aligned `Va64` pointers receive runtime rebases.

Mach-O fixups support `Va64`, `PcRel32`, `Rel32 { origin }`, `Arm64Branch26`,
`Arm64Page21` (ADRP), and `Arm64PageOffset12` (unshifted ADD immediate).
Their instruction, alignment and signed-range constraints are checked. No branch
veneers, arm64e authenticated pointers or legacy runtime binding encoders are
synthesized. Without `enable_dyld`, the builder provides structural output with
build-time addresses; that output does not claim runtime rebasing.

`add_initializers` emits ordered loader pointer arrays. `add_terminators` generates
an initializer thunk that registers callbacks through libSystem's `__cxa_atexit`;
callbacks run in reverse registration order. The builder requires an explicit
libSystem dependency for this registration.
`add_thread_local` provides one initialized TLV template and an Apple three-word
`__tlv_bootstrap` descriptor. It returns the descriptor section; caller code uses
Apple's TLV calling convention. Dyld pins images with TLV descriptors, so their
terminators are validated at process exit rather than ordinary `dlclose`.
`add_unwind` accepts caller-encoded `__TEXT,__eh_frame` records and validates
record lengths. The caller supplies correct CIE/FDE encodings, CFI instructions
and relative `PcRel32` fixups. Compact-unwind synthesis, personalities/LSDA and
additional TLV models are outside the tested profile.

Output remains unsigned. On macOS, run `codesign --force --sign - --timestamp=none IMAGE`, verify it, and reparse the signed result before execution. The acceptance
harness performs those steps and uses `otool`/`dyld_info` independently. The existing
FAT writer packages independently built thin images.

Both `build_with_layout` methods return the ordinary parsed image plus placement
information. Only the reparsed fields have actual on-disk offsets. Layout reports
distinguish file locations from virtual addresses and virtual-only storage.
Writers reject writable executable segments, foreign handles, unsupported storage
and arithmetic overflow instead of silently adjusting requests.

`elf::edit::ElfEdit` and `macho::edit::MachOEdit` edit owned source images through
an isolated candidate and replace the source only after successful validation and
reparsing. Dropping a session or failing commit preserves source bytes and cached
fields. Fixed-capacity replacement zero pads shorter data. Every supported edit
preserves existing mapped virtual addresses; neither session promises arbitrary
executable relayout, compaction or pointer discovery by scanning code.

ELF custom sections must be isolated nonallocated PROGBITS data. Use
`replace_custom_section` within capacity, `grow_custom_section` to append a new
payload, `add_custom_section` to append data and rebuild the section-name/header
tables, or `remove_custom_section` to clear an unreferenced section while retaining
all indices. Growth supports power-of-two alignment up to 4096 bytes. Section
links, relocation targets, symbols and supported table consumers are inventoried;
unknown consumers reject structural edits. `rename_custom_section` uses isolated
section-name capacity. These edits support ELF32/64 and either byte order even
though the builder targets ELF64 little endian.

`add_note_section` and `replace_note_section` accept complete caller-owned,
nonallocated note records; loader-owned notes are rejected. Build-ID policies are
`Reject` by default, `PreserveStale`, or `Remove`. Removal clears GNU build-ID note
identity without moving subsequent records; it does not generate a replacement ID.
Reports expose overwritten and moved file ranges plus build-ID consequences.
`replace_interpreter` and `replace_dynamic_string(tag, occurrence, value)` replace
PT_INTERP and NEEDED/SONAME/RUNPATH strings within verified existing capacity.
Shared/suffix string aliases, version-table consumers and unmodeled references
reject edits; dynamic string-table growth is unsupported.

Mach-O custom payloads use `__CUSTOM`. `replace_custom_section` stays within
capacity; `grow_custom_section` first uses verified zero padding in an isolated single-section
custom segment or its verified zero file gap, extending the segment file size
within its existing virtual capacity. It appends a replacement payload only when
the custom segment is
last in file order; expansion into another segment's VA is rejected.
`add_custom_section` adds a page-aligned custom segment only within verified,
zero-filled command capacity. Images with `__LINKEDIT` must reserve `__CUSTOM`
during construction because adding a segment beyond it would violate native
segment order. `replace_command_string` replaces dylib install
names, dependencies and RPATHs within zero-padded command capacity. Unknown file
range consumers reject payload edits. Chained fixups are traversed to inventory
live bind/rebase slots; edits overlapping those slots are rejected, including
slots outside section extents. Malformed chains and nonempty legacy bind/rebase
streams or external/local relocation tables also reject edits. The chained-fixup
decoder bounds copied names and decoded page entries to eight times its input
size and rejects excessive alias expansion with `ValueTooLarge`.
Signature policy defaults to `Reject`;
`with_signature_policy(..., SignaturePolicy::Strip)` removes supported final
`__LINKEDIT` signature command/blob, shrinks its segment extents and reports required
external re-signing.

`edit_fat_slice` applies fixed-capacity edits while preserving the FAT layout,
padding, architecture metadata and other slices verbatim. `rebuild_fat_slice`
permits thin-slice growth and uses the canonical FAT writer to rebuild container
offsets/alignment. It preserves every other thin slice and CPU/subtype/alignment
metadata; FAT width, byte order and padding may normalize. Report ranges are
relative to the selected thin image.

Generate and validate examples in a development shell:

```sh
cargo run --features elf,write --example elf_hello -- /tmp/elf-hello
/tmp/elf-hello
cargo run --features elf,write --example elf_pie -- /tmp/elf-pie --stripped
cargo run --features elf,write --example elf_shared -- /tmp/libhexspell.so
cargo run --features macho,write --example macho_hello -- arm64 /tmp/macho-arm64
cargo run --features elf,write --example elf_edit -- /tmp/elf-hello /tmp/elf-edited
# On macOS, including external signing and native loader checks:
python3 tests/scripts/macho-runtime.py /tmp/hexspell-macho --arch arm64
python3 tests/scripts/macho-runtime.py /tmp/hexspell-macho --arch x86_64
python3 tests/scripts/elf-macho-runtime.py /tmp/hexspell-elf-macho
```

See the [implementation plan](elf-macho-generation-plan.md) and
[validation matrix](elf-macho-generation-validation.md) for implementation milestones,
supported loader profiles and recorded native acceptance evidence.


## Signature containers and external signers

Enable `write` with the appropriate format. These APIs edit containers and leave
cryptographic signing, hash rules, certificate-chain verification and policy to
an external signing library such as `signcode-rs` or Apple `codesign`.

### PE certificate tables

`PE::owned_certificates()` copies each `WIN_CERTIFICATE` revision, type, opaque
payload and alignment padding. `CertificateTableOwned::serialize()` preserves
unknown records and fitting original padding; resized padding is zero-filled.
`append_certificate`, `replace_certificates` and `remove_certificates` update the
security directory and PE checksum transactionally. Appending reads existing
records from the current buffer, even if cached directory fields are stale.
Existing tables must be isolated EOF overlays. Bytes preceding the table remain
in place; post-table overlays and aliases into sections, debug payloads or COFF
metadata are rejected.
An absent physical security directory slot is rejected rather than growing headers.

```rust
# #[cfg(all(feature = "pe", feature = "write"))] {
use hexspell::pe::{PE, certificate::CertificateOwned};
# fn attach(image: &mut PE, pkcs7: Vec<u8>) -> Result<(), hexspell::errors::FileParseError> {
image.append_certificate(&CertificateOwned::pkcs_signed_data(pkcs7))?;
let records = image.owned_certificates()?;
image.replace_certificates(&records)?;
image.remove_certificates()?;
# Ok(()) }
# }
```

Payload attachment does not imply a valid signature. Finish image edits before
signing; the signing backend must apply Authenticode digest rules, including any
EOF alignment needed for an unsigned input. Appending a record preserves existing
record bytes but does not assert that existing signatures remain valid.

### Mach-O embedded signatures

`MachO::code_signature()` exposes the real `dataoff` and `datasize` Fields from
`LC_CODE_SIGNATURE`; `code_signature_data()` returns its bounded opaque blob.
Reading works independently of `write`. Duplicate commands are rejected.

Writing supports thin little-endian x86-64/arm64 images with an isolated final
`__LINKEDIT` and unused load-command padding. `reserve_code_signature(size)`
reuses equal-size existing reservations without changing their bytes; otherwise it
creates/replaces the command, aligns its blob to 16 bytes, and updates the segment
file/virtual extents without moving existing payloads. It returns the final
`signing_range` and `signature_range`. The signer must hash the prepared image,
then call `write_code_signature(blob)` with exactly the reserved byte count.
Every byte outside the blob remains unchanged during installation. Resizing
requires reserving again and recomputing the digest. The full blob is opaque,
including Apple SuperBlob indexes, CodeDirectories, CMS and entitlement data.

`remove_code_signature()` removes a supported final command/blob transactionally.
Unknown reference-bearing commands, aliased ranges and overlapping mappings are
rejected, including an `LC_MAIN` entry point in padding consumed by a reservation.
For FAT files, edit/rebuild the selected thin slice using the FAT helpers;
this API does not directly change a FAT container. Verify the result with the
signing backend and platform tools before execution.

### ELF signature storage

ELF can store signature bytes in a custom section or note, but it has no universal
PE-style certificate table or Mach-O-style signing command. Such bytes need an
agreed verifier and digest/exclusion scheme; an ordinary loader does not gain a
verification policy simply because a signature section exists.

Linux kernel module signing uses an appended signature outside the ELF container,
not an ELF section ([kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)).
IMA commonly stores signatures in the filesystem `security.ima` extended attribute;
appended module-style signatures are another policy-dependent option
([Linux integrity documentation](https://github.com/linux-integrity/ima-doc/blob/main/ima-concepts.rst)).
HexSpell supports the modern Linux module-style PKCS#7 appended container:

- `ELF::appended_signature()` lazily reads the outermost trailer; the standalone
  `signature::AppendedSignature::parse()` also accepts raw byte buffers.
- `AppendedSignature` exposes real `Field` offsets for all twelve metadata bytes,
  plus `signed_range`, `signature_range`, `signed_data(buffer)` and `data(buffer)`.
  `sig_len` is **big endian even in little-endian ELF files**.
- With `elf,write`, `set_appended_signature(pkcs7)` appends or replaces the outermost
  trailer; `remove_appended_signature()` removes only that trailer. Both preserve
  the signed prefix exactly and reject malformed trailers or ELF-owned extents
  which alias the signature. Existing prefix overlays and earlier stacked trailers
  are retained. No header offsets, checksum fields or padding bytes are introduced.

```rust
# #[cfg(all(feature = "elf", feature = "write"))] {
use hexspell::elf::ELF;
# fn attach(image: &mut ELF, detached_cms: &[u8]) -> Result<(), hexspell::errors::FileParseError> {
image.set_appended_signature(detached_cms)?;
let trailer = image.appended_signature()?.unwrap();
let signed_payload = trailer.signed_data(&image.buffer)?;
let signature = trailer.data(&image.buffer)?;
# let _ = (signed_payload, signature);
image.remove_appended_signature()?;
# Ok(()) }
# }
```

The wire format is `[signed prefix][opaque CMS][12-byte metadata][28-byte marker]`.
The type is 2 (PKCS#7), all unused metadata is zero, and the length is a big-endian
u32. Legacy non-PKCS#7 types are unsupported. A complete EOF marker with malformed
metadata is an error; absent or partial markers are not detected as signatures.
This is an opaque container API: it does not parse CMS, create hashes, establish
trust, or enable kernel appraisal. Finish all ELF edits before signing the exact
prefix, including any overlay bytes. Any later prefix modification invalidates
its signature. Operate on decompressed ELF bytes, not `.ko.xz` or `.ko.zst` wrappers.

Debian uses this Linux appended-signature mechanism for kernel modules; DKMS can
sign locally built modules for Secure Boot ([Debian Secure Boot documentation](https://wiki.debian.org/SecureBoot)).
Ordinary Debian programs generally rely on APT's authenticated repository metadata
and package checksums, not per-ELF embedded signatures
([apt-secure](https://manpages.debian.org/testing/apt/apt-secure.8.en.html)).
Custom ELF sections/notes remain available for application-specific schemes.

```sh
cargo run --features elf,write --example elf_signature -- attach module.ko signature.p7s signed.ko
cargo run --features elf,write --example elf_signature -- extract signed.ko payload.ko signature.p7s
cargo run --features elf,write --example elf_signature -- roundtrip signed.ko copied.ko
cargo run --features elf,write --example elf_signature -- remove signed.ko unsigned.ko
```
