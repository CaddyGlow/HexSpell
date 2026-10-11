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

Enable the opt-in `pe-write` feature (disabled by default). It adds no dependencies
and works with `no_std` plus `alloc`; `std` is needed only for file APIs/examples:

```toml
[dependencies]
caddy-hexspell = { version = "2.0", features = ["pe-write"] }
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
cargo run --features pe-write --example pe_hello -- x86 hello-x86.exe
cargo run --features pe-write --example pe_hello -- x64 hello-x64.exe
cargo run --features pe-write --example pe_dll -- x86 demo-x86.dll
cargo run --features pe-write --example pe_dll -- x64 demo-x64.dll
cargo run --features pe-write --example pe_resources -- hello-x64.exe edited-x64.exe preserve
```

On Windows, run `pe_dll_load` built for the DLL's architecture with its absolute
path; append `--force-relocation` to reserve the preferred base before loading.
The Hello examples exercise TLS-before-entry, dereferenced relocated pointers,
imports, manifests, RCDATA, strings, versions, icons, and x64 unwind metadata.
See [validation scripts](../tests/scripts/README.md) for independent inspection
and Windows runtime checks, including negative controls and forced relocation.

## Features and migrating to 2.0

| Feature | Default | Surface |
| --- | --- | --- |
| `std` | Yes | Filesystem I/O and standard-library error conversions |
| `pe` | Yes | PE parsing and existing section/layout editing |
| `elf` | Yes | ELF parsing and editing |
| `macho` | Yes | Mach-O parsing and editing |
| `common` | Yes | Public `reloc`, `strings`, `validation`, and `write` helpers; format-specific helpers follow enabled formats |
| `pe-write` | No | New PE construction, owned resource editing, and typed resource codecs; implies `pe` |

Core `field`, `errors`, and `utils` remain available in every configuration. Parsers
retain the private string-reading machinery they need when `common` is disabled.
`common` itself does not enable any format; generic helpers work by themselves.

**Breaking:** `default-features = false` now disables formats and the common helper
interface as well as `std`. To preserve the previous no-std surface, explicitly
enable `features = ["pe", "elf", "macho", "common"]`. Default users keep all
existing formats and helpers. Examples of narrower configurations:

```toml
# PE parser only, no standard library or public common helper interface.
caddy-hexspell = { version = "2.0", default-features = false, features = ["pe"] }
# In-memory PE generation and resource editing only.
caddy-hexspell = { version = "2.0", default-features = false, features = ["pe-write"] }
# Shared fields plus generic helpers, with no format parser.
caddy-hexspell = { version = "2.0", default-features = false, features = ["common"] }
```

Choose one dependency declaration. Feature unification is additive: another
dependency may enable additional formats for the same package in the build graph.
