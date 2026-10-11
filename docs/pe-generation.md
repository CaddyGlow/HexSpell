# PE generation and resource editing proposal

Status: implemented behind the opt-in `write` feature with `pe`. This document retains
the original design contracts; actual API names and usage are documented in the
[guide](guide.md#pe-generation-and-resource-editing). See the
[implementation plan](pe-generation-plan.md) for delivery and validation details.

## Goal

Generate complete PE executables from Rust without a template executable, linker,
Windows SDK, or runtime dependencies. Support multiple independently generated
images and both x86 PE32 and x64 PE32+. The first executable displays “Hello” with
`USER32.dll!MessageBoxW` and terminates through `KERNEL32.dll!ExitProcess`.
Include imports, working base relocations, a TLS callback, and resources. Extend the same resource
serialization machinery to editing existing executables.
Also generate x86 and x64 DLLs exposing a small callable API, with a matching
loader example to verify the exports on Windows.

HexSpell supplies binary layout and serialization. Callers supply machine-code
bytes; an assembler, Rust compiler backend, and general COFF linker are outside
this proposal. Small reviewed instruction sequences live in the examples.

## Current foundation

| Capability | Current implementation | Required addition |
| --- | --- | --- |
| Headers and sections | PE32/PE32+ parsing, `Field` offsets | Initial header emission |
| Layout | Section insertion and layout synchronization | Complete-image layout planning |
| Imports | Lazy descriptor, thunk, and name parsing | Import serializer and IAT handles |
| Exports | Lazy `PE::exports()` and export iterators | Export directory/table serialization |
| Relocations | Lazy parsing and image-base application | Fixup recording and block emission |
| TLS | Lazy `PE::tls()` directory parsing | Directory and callback-array serialization |
| Resources | Lazy generic directory tree parsing | Payload views, serialization, editing |
| Output | Owned buffer and file writing | Build result with resolved layout |

Existing section edits have partial support for embedded RVA changes. New resource
editing must therefore preserve existing section RVAs rather than assume arbitrary
section movement is safe.

## Construction API

Add `pe::build` with an owned `PeBuilder`. Construction data has no `Field` offsets
until emitted. `build()` returns an ordinary owned `PE` parsed from the emitted
buffer, giving every modeled field its actual file offset and size. Keep existing
parsers lazy and preserve the current patching API.

Proposed operations:

| Operation | Contract |
| --- | --- |
| `PeBuilder::new(target)` | Explicit x86 or x64 target; coherent machine/header defaults |
| `set_image_kind(kind)` | Executable or DLL; emits coherent COFF characteristics |
| `add_section(spec)` | Returns a stable section handle; supports zero-filled virtual tails |
| `define_symbol(section, offset)` | Returns a handle independent of final RVA |
| `add_import(dll, symbol)` | Name or ordinal; returns an IAT-slot handle |
| `set_exports(spec)` | DLL name, ordinal base, and named/ordinal-only local symbols |
| `add_fixup(location, target, kind)` | Registers a checked address or displacement write |
| `set_entry_point(symbol)` | Entry must resolve into executable file-backed bytes |
| `set_tls(spec)` | Template, writable index symbol, and ordered callback symbols |
| `set_resources(resources)` | Attaches an owned resource model |
| `build()` | Resolves layout, serializes, validates, and returns `Result<PE, FileParseError>` |

Use existing section characteristics and header types where suitable. Keep builders
in `alloc`; filesystem output stays behind `std`. Reuse `FileParseError` where it
expresses the failure; review semver consequences before adding public variants.
Reject unsupported target/fixup combinations, unresolved or foreign handles,
overlapping fixup writes, overflow, out-of-range writes, and invalid alignment.
Use checked arithmetic throughout. Failed builds and edits leave inputs unchanged.

Use separate builder instances for multiple outputs. No global address allocator
or mutable shared state. Deterministic defaults include zero timestamps and stable
table ordering; callers can explicitly override supported header values.

### Layout and fixups

1. Validate options, section sizes, symbols, and imports.
2. Measure generated tables and reserve section/header space.
3. Assign aligned file offsets and section RVAs, including virtual-only tails.
4. Resolve symbols and IAT slots; emit tables and patch caller bytes.
5. Emit headers, directory entries, padding, and optional checksum.
6. Parse the result and run relevant consistency checks before returning it.

Table sizes must be known before placement. Relocation block size depends on final
fixup page groupings: place non-relocation sections first, then append `.reloc`.
Reject cyclic layout dependencies instead of silently moving already resolved data.

Fixup kinds distinguish `Rva32`, `Va32`, `Va64`, and signed `Rel32` with an explicit
displacement origin. RVA and relative references do not generate base relocations.
Absolute VA writes generate `HIGHLOW` for x86 or `DIR64` for x64. Reject truncation
and displacements outside the signed 32-bit range.

Expose a resolved layout report for inspection: section handles, file offsets,
RVAs, symbol locations, and IAT locations. Reserve `Field` for actual emitted fields.

## MessageBox acceptance examples

Provide `examples/pe_hello.rs` with explicit target and output arguments. Running
it on Linux must generate a Windows executable using only HexSpell and the Rust
standard library. Generate x86 and x64 files independently from the same logical
input. Add resource variants after the resource milestones land.

| Section | Contents |
| --- | --- |
| `.text` | Entry code calling MessageBoxW and ExitProcess; TLS callback code |
| `.rdata` | UTF-16 greeting/title, greeting pointer, TLS directory and callback array |
| `.data` | Writable TLS index (`u32`) and callback completion flag |
| `.tls` | Small initialized TLS template |
| `.idata` | Descriptors, lookup tables, IAT, DLL names, hint/name records |
| `.reloc` | Relocations for actual absolute pointer writes |
| `.rsrc` | Manifest and custom data; icon/version variants later |
| `.pdata` / `.xdata` | x64 runtime function entries and unwind information |

Use GUI subsystem, executable/readable code, writable IAT storage, and appropriate
data permissions. Set coherent ASLR flags and retain relocations. Import tables
include their required terminators and target-sized thunk slots. Populate import,
IAT, relocation, TLS, resource, and x64 exception directories when present.

The x86 sequence follows the Windows API calling convention. The x64 sequence
provides shadow space and correct stack alignment, with matching unwind metadata
for its non-leaf entry function. The greeting pointer is actually dereferenced, so
relocation tests exercise observable behavior even when code uses RIP-relative
references elsewhere. Checksum and header summary values follow the final layout.

### TLS callback behavior

Both targets include one callback with the Windows TLS callback signature
`void NTAPI callback(void *module, DWORD reason, void *reserved)`. On
`DLL_PROCESS_ATTACH`, it sets a completion flag in `.data` and returns. Other
notifications leave the flag unchanged. The entry point checks the flag before
displaying “Hello” and exits with a distinct nonzero status if it was not set.
Keep MessageBoxW in the entry point; the callback performs only the memory write.
This makes execution before the entry point observable without GUI work under the
loader lock.

Serialize `IMAGE_TLS_DIRECTORY32` (24 bytes) or `IMAGE_TLS_DIRECTORY64` (40 bytes).
Its data-directory entry uses an RVA; its template start/end, index, and callback
array addresses are VAs. The template end is exclusive. Emit a pointer-sized,
null-terminated array containing the callback VA, and generate base relocations
for all nonzero address fields and callback pointers. Keep the terminator zero
when rebasing. The TLS index storage remains four writable bytes on both targets.
Set template alignment explicitly and use zero additional zero-fill for this example.
These layout requirements follow the
[PE TLS specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section).

The x86 callback uses the Windows `stdcall` convention, including argument stack
cleanup. The x64 callback follows the Windows x64 ABI; a leaf callback that neither
adjusts the stack nor modifies nonvolatile registers needs no unwind record.
If its implementation becomes non-leaf, emit matching unwind metadata.

“Complete” means all structures needed by these examples. Forwarded exports, delay
imports, CLR metadata, signing, and arbitrary compiler-generated exception data
are separate future work.

## DLL acceptance examples

Provide `examples/pe_dll.rs` to generate `hexspell_demo.dll` for either target from
scratch. Set `IMAGE_FILE_DLL` as well as the executable-image characteristic.
Supply a minimal `BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)` entry point that
returns `TRUE`, with no external calls. Its behavior follows the
[DllMain contract](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain).

Export three small functions with an explicit Windows `extern "system"` ABI:

| Public name | Ordinal | Signature and behavior |
| --- | --- | --- |
| `Add` | 1 | `u32 Add(u32 a, u32 b)` returns their wrapping sum |
| `GetGreeting` | 2 | `const u16 *GetGreeting(void)` returns a static NUL-terminated UTF-16 greeting |
| Ordinal only | 3 | `u32 GetVersion(void)` returns `1`; its internal symbol name is not exported |

Publish exactly the spelled names above without implicit x86 decoration. On x86,
the two-argument `Add` uses callee stack cleanup; on x64 all functions follow the
Windows x64 ABI. The returned greeting is read-only and valid until DLL unload.
Make `GetGreeting` read an absolute pointer slot in `.rdata`, so the DLL exercises
working base relocations on both targets. Keep these functions and DllMain leaf
routines; emit unwind metadata if their implementations require it.

Use `.text`, `.rdata`, `.edata`, and `.reloc`. Emit the export directory, DLL name,
export address table, name pointer table, and name ordinal table. The initial
example has ordinal base 1, three address slots, and two named entries. Export
addresses and name pointers remain 32-bit RVAs on both targets; name ordinal slots
are 16-bit zero-based address-table indices. Sort names lexically while keeping
their ordinal mapping intact. Bound the export directory range so local code RVAs
cannot be mistaken for forwarder strings. These rules follow the
[PE export specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only).

The serializer supports explicit ordinals and gaps (zero address slots), rejecting
duplicate names/ordinals, embedded NULs, invalid symbols, and unrepresentable table
indices. Forwarders and data exports can follow later. The minimal DLL does not
require imports or TLS; the Hello executable remains the TLS acceptance example.

Provide `examples/pe_dll_load.rs` as a Windows-only loader using direct system FFI
and no added crate dependencies. Use `LoadLibraryW` with an absolute path, resolve
both named functions and ordinal 3 with `GetProcAddress`, check `Add(2, 3) == 5`,
the greeting, and version `1`, then call `FreeLibrary`. Function pointers must use
the declared ABI. Read the greeting before unloading. Use a loader matching the
DLL architecture; a 64-bit process cannot load the x86 DLL.

## Resource model and editor

Keep `ResourceTree` as the on-disk view. Add a distinct owned editable model with
numeric and UTF-16 names, directory metadata, leaf code pages, and opaque payloads.
Use raw UTF-16 units internally so loading and rewriting does not lose names that
cannot be represented faithfully by the existing decoded `String` view.

Offer lookup/enumeration and add, replace, remove, and rename by path. Conventional
Windows resources use type/name/language keys; retain generic paths for trees with
other depths. Duplicate keys require an explicit replacement operation. Preserve
unknown resource types and payloads.

The serializer measures directories, names, leaf descriptors, and payloads before
writing them. Canonical ordering places names before numeric IDs. It distinguishes
resource-root-relative metadata offsets from payload RVAs and applies required
alignment. Validate counts, high-bit encodings, sizes, cycles, and payload extents.
Payloads can reside outside the resource metadata section: read through checked
RVA translation rather than assuming they are contiguous with the tree.

For editing existing PEs:

1. Parse resources and copy metadata and referenced payloads into the owned model.
2. Apply edits without mutating the source image.
3. Serialize into a replacement region that fits safely, or append a new section
   using existing section-insertion helpers; preserve pre-existing section RVAs.
4. Update the resource directory RVA/size, layout summaries, and checksum; reparse
   before committing the candidate buffer.

Do not overwrite shared or unverified ranges merely because the new data fits.
Appending replacement resources may leave unreachable old bytes; compaction is
outside the initial editor. Preserve overlays and correctly adjust file-offset
references, including the certificate-table offset when raw file data moves.
Any image edit invalidates an existing Authenticode signature: the editor must
report that outcome and provide an explicit preserve-bytes or strip policy.
No signing implementation is included.

Typed resource support follows generic editing:

| Resource | Planned support |
| --- | --- |
| Manifest / RCDATA | Opaque bytes; convenience UTF-8 manifest access |
| String table | Sixteen-entry UTF-16 blocks, language-aware updates |
| Version information | Aligned nested blocks; preserve unknown children |
| Icon | ICO import/export, coordinated group/icon IDs and references |
| Cursor, menu, dialog, bitmap | Generic payload editing initially; typed codecs later |

“Resource editor” initially means a library API and Rust examples. A GUI or CLI
application needs its own scope.

## Delivery roadmap

| Milestone | Deliverables | Exit criteria |
| --- | --- | --- |
| 1. Construction | Header writer, layout planner, symbols, raw sections | PE32/PE32+ parse round trips; exact offsets; malformed input rejected |
| 2. Imports and exports | Descriptor/ILT/IAT serialization, name/ordinal imports, export directory/tables | Existing parsers recover imports/exports; thunk widths, named and ordinal-only exports tested |
| 3. EXE and DLL examples | VA/relative fixups, reloc serializer, TLS emission, x64 unwind records, Hello and DLL/loader examples | Both targets run on Windows; TLS precedes EXE entry; DLL exports callable; forced relocation succeeds |
| 4. Generic resources | Checked payload access, lossless owned model, serializer | Named/ID/multilingual trees round trip; malformed extents rejected |
| 5. Resource edits | Transactional replacement/append, signature policy | Grow/shrink/add/remove preserve unrelated bytes and existing RVAs |
| 6. Typed resources | Manifest, strings, version, icons; examples | Windows resource APIs read edited values; unknown data survives |

Milestones 1–3 provide generation; 4–5 provide the generic resource editor.
Each milestone is a separate reviewable change, with tests and public documentation.
No runtime dependencies are added. Update coverage only when functionality ships.
Add user-facing changelog entries with implementation; apply semver rules if any
existing API must change.

## Validation

Test generated buffers without checked-in binaries where possible. Cover PE32 and
PE32+, deterministic multiple builds, nondefault bases/alignments, empty and large
tables, duplicate/invalid handles, overflow, and signed displacement boundaries.
Check exact `Field` offsets and sizes after reparsing. Test rebasing by verifying
every expected absolute pointer changes and relative/RVA references do not.
Reparse TLS with `PE::tls()` and check directory field offsets/widths, template
bounds, writable index storage, callback-array order and termination, and every
required relocation. Cover zero and multiple callbacks in serializer tests.
Reparse DLL exports through `PE::exports()` and both export iterators. Verify exact
names, ordinals, table counts, slot offsets, lexical ordering, ordinal-only entries,
and 32-bit RVAs in both layouts. Cover ordinal gaps, nondefault ordinal bases,
duplicate rejection, overflow, and deterministic emission.

Resource tests cover named UTF-16 entries, language variants, unknown payloads,
metadata, external payload ranges, growth, removal, and failure atomicity. Include
regressions for each parser bug fixed during the work. Existing resource-name
high-bit handling needs a spec-based regression before relying on it for editing.

Use an independent PE reader or inspection tool in an optional validation job;
round trips through HexSpell alone cannot prove Windows loader compatibility.
Windows tests launch both examples, identify and dismiss the greeting dialog,
and verify exit status, including the entry-point TLS completion check. Confirm
the callback receives `DLL_PROCESS_ATTACH` before entry on both targets, including
when relocated. Exercise loading at a different base with a controlled
test harness; observing ASLR once is insufficient. Verify x64 unwind records with
Windows runtime APIs. Runtime checks are separate from Linux structural tests.
Run matching x86/x64 DLL loaders and check all three exported results, including
after forcing the DLL away from its preferred base. Keep ordinal-gap validation
structural; do not call unresolved gap addresses. Verify unload succeeds.
Record provenance and rebuild recipes for any committed binary fixtures.

Finish implementation changes with `cargo fmt`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test`.

## Specification references

- [Microsoft PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [Microsoft x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
