# PE generation and resource editing implementation plan

Status: implementation completed in the working tree under the opt-in `pe,write`
feature. The steps below retain their planning rationale; current API names and
feature selection are in [the guide](guide.md#pe-generation-and-resource-editing).
Runtime and structural verification results are recorded in
[the validation report](pe-generation-validation.md).

This plan implements [the proposal](pe-generation.md). The proposal defines scope;
this document defines implementation order, decisions, code locations, and exit
criteria. Proposed file and API names may be adjusted before their first release.
Keep the existing parsing and patching APIs compatible and add no runtime dependencies.

## 1. Delivery strategy

Build one complete path at a time: raw image → tables → executable examples →
resources → editing → typed codecs. Implement PE32 and PE32+ together at each step,
using one target description rather than duplicating the pipeline. Keep serializers
independent of placement: measure once, assign addresses, then emit into checked slices.

Use the following review units. A milestone can contain several commits, but must
meet its exit criteria before being described as complete in public documentation.

| Unit | Proposal milestone | Work | Depends on |
| --- | --- | --- | --- |
| P0 | Preparation | Contracts, synthetic test support, baseline | None |
| P1 | 1 | Builder, checked placement, header emission, layout report | P0 |
| P2 | 2 | Imports and stable IAT references | P1 |
| P3 | 2 | Named and ordinal-only exports | P1 |
| P4 | 3 | Fixups and relocation blocks | P1; integrate P2 handles |
| P5 | 3 | TLS and minimal x64 exception metadata | P4 |
| P6 | 3 | Hello EXE, DLL, loader, Windows acceptance harness | P2–P5 |
| P7 | 4 | Resource parser regressions and checked payload access | P0 |
| P8 | 4 | Lossless resource model and serializer; builder integration | P1, P7 |
| P9 | 5 | Transactional resource replacement and signature policy | P8 |
| P10 | 6 | Manifest and string-table codecs | P9 |
| P11 | 6 | Version-information codec | P9 |
| P12 | 6 | ICO/group-icon codec and final acceptance | P9; integrate P10–P11 |

Recommended execution order is P0 through P12. P7 is independent of generation and
can be moved earlier if its parser fix is needed elsewhere. Do not make generation
wait for typed resources. Add resource variants to the P6 examples as P8–P12 land.

## 2. Existing code to reuse and limitations to address

| Existing location | Reuse | Important limitation |
| --- | --- | --- |
| `src/pe/mod.rs` | `PE::from_buffer`, lazy directory methods, checksum, insertion | Parsing alone is not loader validation; insertion mutates before every possible error is known |
| `src/pe/header.rs`, `coff.rs`, `dos.rs`, `section.rs` | Constants, target/header types, actual field layouts | New construction specifications must not pretend to have file offsets |
| `src/pe/layout.rs` | `FileOffsetFixups`, optional-header growth, section editing | Existing arithmetic and last-section assumptions need preflight checks; `sync_layout` only updates selected summaries |
| `src/pe/import.rs`, `export.rs`, `read.rs` | Independent consumer APIs for serializer tests | Validate emitted bytes directly too, to avoid shared parser/writer mistakes |
| `src/pe/relocation.rs`, `tls.rs`, `exception.rs` | Relocation application and directory views | Exception support models runtime-function entries, not a general unwind encoder |
| `src/pe/resource.rs` | Existing on-disk tree and metadata fields | Names are lossy strings; payload contents are not read; name offsets are currently not high-bit masked |
| `src/validation.rs` | Range checks and PE consistency diagnostics | Supplement with builder-specific invariants and complete range validation |
| `tests/pe.rs`, `tests/pe_edit.rs`, `tests/no_std.rs` | Regression conventions and feature-mode checks | Existing named-resource fixture omits the name high bit; fix it with the regression |
| `tests/scripts/pefile_oracle.py`, `tests/pefile/` | Optional independent inspection infrastructure | Keep Python/tool availability separate from ordinary library tests |

The findings above are from source inspection, not new test results. Fix only
limitations required by this work, each with a failing regression first.

## 3. Contracts to settle in P0

Record these decisions in rustdoc and tests before serializers depend on them.

1. **Target and defaults.** Explicit x86/x64 target, executable/DLL kind, zero
   timestamps, documented image bases, subsystem, stack/heap values, and alignments.
   Initially support conventional loader-compatible alignments; reject unsupported
   low-alignment modes explicitly. Check target address limits as well as field widths.
2. **Build ownership.** Prefer `build(&self) -> Result<PE, FileParseError>` so a
   failed build leaves the specification reusable. Add `build_with_layout(&self)`
   returning the same image plus a resolved report; implement both through one path.
   Do not change the proposal's ordinary `PE` return into a mandatory wrapper.
3. **Handle ownership.** Section, symbol, and import handles must have distinct
   types, private fields, and builder identity as well as an index. An index alone
   cannot reject another builder's handle. One alloc-only option is a private
   `Rc` identity token held by builder and handles, checked with pointer identity.
   Document the resulting `!Send`/`!Sync` tradeoff; if cross-thread builders are
   required, settle an alternative before publishing. Do not derive builder cloning
   with ambiguous handle ownership. Identity never influences emitted bytes.
4. **Symbol bounds.** Distinguish addressable virtual positions from writable
   file-backed ranges. Allow end markers for TLS/unwind exclusive ends, but never
   accept an end marker or virtual-only location as executable entry bytes.
5. **Fixup semantics.** A location is a section plus byte offset; a target is a
   symbol or IAT slot. Define checked addends and an explicit origin for `Rel32`.
   Initially allow `Rva32`/`Rel32` on both targets, `Va32` on x86, `Va64` on x64.
   All absolute writes are image-relative VAs, not arbitrary process addresses.
6. **Generated sections.** Reserve internal section identities before header sizing.
   Keep caller insertion order and deterministic generated-section order; distinguish
   identity from the eight-byte display name. Reject conflicting reserved names
   initially, with a documented error, instead of silently merging caller data.
7. **Errors and compatibility.** Map malformed contracts to `InvalidFileFormat`,
   range errors to `BufferOverflow`, narrowing/overflow to `ValueTooLarge`, and
   unsupported modes to `UnsupportedFeature`. Avoid new variants in the existing
   exhaustive enum without semver review. Preserve Rust 1.88 compatibility.
8. **Resources and edits.** Keep the existing `ResourceTree` public shape. New owned
   types preserve raw UTF-16 and all modeled metadata. Resource commit uses a
   candidate buffer and an explicit signature policy with an outcome report.

P0 completion: contract tests and small API sketches cover both targets, repeated
builds, two builder instances, foreign handles, and failed-build reuse. Capture a
baseline of existing checks; do not add public unimplemented methods.

## 4. Suggested code organization

Create modules only as their units land; keep implementation details private.

```text
src/pe/build/
  mod.rs          public builder/specifications and orchestration
  layout.rs       checked measurement, placement, resolved report
  headers.rs      initial DOS/COFF/optional/section header emission
  fixup.rs        address resolution and relocation collection
  imports.rs      import measurement/emission
  exports.rs      export measurement/emission
  relocations.rs  page grouping and block emission
  tls.rs          TLS measurement/emission
  exceptions.rs   narrow x64 runtime-function registration/emission
src/pe/resource/
  owned.rs        editable raw UTF-16 tree and path operations
  write.rs        measured resource serialization
  edit.rs         candidate-image commit and result reporting
  strings.rs     string-table codec
  version.rs     version-information codec
  icon.rs        ICO/group-icon codec
```

Keep `src/pe/resource.rs` as the existing module root with child declarations; no
file move is required. Manifest/RCDATA conveniences can live in `owned.rs` until
their size warrants separation. Use existing `Field` types only after emission.

Put generation tests in `tests/pe_build.rs`, resource-model/codec tests in
`tests/pe_resources.rs`, parser regressions in `tests/pe.rs`, and structural-edit
regressions in `tests/pe_edit.rs`. Share small fixture constructors under
`tests/support/`; do not couple expected offsets to the production planner.

## 5. P1 — construction and layout

Implementation sequence:

1. Add the target/specification types and private checked arithmetic/write helpers.
   Reject invalid alignment, overlong section names, virtual sizes smaller than
   supplied bytes, and unsupported image options before allocating the output.
2. Measure complete header and section-table storage, including generated sections.
   Plan raw file ranges separately from virtual ranges. Pure zero-fill sections
   consume virtual space without forcing corresponding file bytes.
3. Compute placement using occupied extents, including aligned raw data, virtual
   tails, and header coverage. Validate disjoint ranges and every narrowing conversion.
   Check the supported loader section-count limit before allocating large tables.
4. Emit initialized DOS/header bytes and all section headers. Populate coherent
   machine, optional-header magic/size, directory count, entry RVA, image base,
   code/data totals, base fields, image/header sizes, characteristics, and checksum.
   Keep explicit PE32 versus PE32+ layout tables; never infer one from the other.
5. Resolve symbols to RVA/VA and optional file offset. A virtual-only symbol has no
   file offset. Return a report keyed by the original handles.
6. Reparse and apply relevant consistency checks before returning. Explicitly
   validate anything the existing parser intentionally accepts more permissively.

Tests: exact header/section field offsets and widths; multiple sections; empty
payloads and virtual tails; raw sizes crossing alignment boundaries; valid nondefault
bases/alignments; deterministic bytes across independent builders; invalid entries;
overflow and bad options without giant allocations. Patch a returned `Field`, then
reparse to prove the normal editing API works.

Exit: PE32 and PE32+ synthetic images are structurally valid and usable through the
existing API, with no template fixture and no dependency additions.

## 6. P2 and P3 — imports and exports

### P2: imports

Maintain stable import identities independent of serialized order. Define and test
duplicate-import behavior (recommended: exact duplicate returns the existing slot;
do not silently normalize symbol case). Measure descriptors, ILT, IAT, strings, and
hint/name records before placement. Emit target-width thunk entries, name/ordinal
forms, and all terminators; leave binding timestamps unset. Collect IATs into a
contiguous region so the IAT directory has a precise range. Use writable storage.

Tests: name and ordinal imports together, multiple DLLs, duplicate requests,
embedded NUL rejection, ordinal limits, empty input, alignment/padding, descriptor
termination, separate ILT/IAT locations, slot widths, and resolved handles. Compare
both `imports()` and `imports_iter()` plus raw slot bytes.

### P3: exports

Measure the DLL name, directory, address slots including gaps, name pointers, and
name ordinal indices. Sort names independently of ordinal order. Check ordinal-base
arithmetic, sparse-table allocation sizes, duplicates, index representability, and
executable local targets. Keep the directory's range confined to export data so
code is not interpreted as a forwarder. Reject forwarders/data exports initially.

Tests: the three proposal exports on both targets, ordinal-only entries, gaps,
nondefault base, deliberately unsorted input names, duplicate names/ordinals, NULs,
invalid targets, overflow, deterministic bytes, and directory field offsets. Compare
`exports()`, `exports_iter()`, and `export_functions_iter()` with direct table reads.

Exit: milestone 2 table consumers recover the intended logical inputs on both
targets; no runnable machine-code examples are needed yet.

## 7. P4 — fixups and relocations

Implement a single resolver used by caller fixups and generated tables. Validate
write widths and overlap against initialized section bytes before writing. Compute
relative differences in a sufficiently wide signed intermediate before converting.
Sort relocation locations by page and offset; include each absolute site once.

Reserve the `.reloc` section header before placing other sections. Place all
non-relocation data, collect final absolute sites, measure blocks, then append
`.reloc`. Include required block padding. Do not allow fixups targeting relocation
contents in the initial API; reject dependencies that require replanning addresses.
Finalize flags coherently with the actual relocation policy, including images with
no absolute sites. Document fixed-base behavior instead of emitting contradictory flags.

Tests: every fixup kind, IAT targets, signed minimum/maximum and one step beyond,
foreign/invalid handles, overlapping writes, virtual-tail writes, page boundaries,
odd block entry counts, target mismatch, and VA overflow. Rebase a copy with
`apply_image_base`; compare every absolute site and prove RVA/relative bytes and
padding remain unchanged. Exercise both positive and negative base deltas.

Exit: a known pointer graph survives rebasing on both targets, and failed builds
leave caller sections and builder state unchanged.

## 8. P5 — TLS and x64 exception information

TLS tasks:

- Measure template, directory, and callback array through the same layout pipeline.
- Validate template bounds/alignment, four writable index bytes, executable callback
  symbols, and supported zero-fill options. Distinguish exclusive end symbols.
- Register generated address writes through the shared fixup engine. Preserve null
  callbacks/terminators during rebasing and keep directory-entry addresses separate
  from the TLS structure's address fields.
- Test zero, one, and multiple callbacks; directory field offsets/widths; template
  bounds; permissions; invalid index storage; and the exact relocation-site set.

For x64, add only the runtime-function registration needed by the examples: begin
and exclusive end symbols plus an unwind-data symbol. Permit caller-supplied reviewed
unwind bytes; do not implement a general assembler or exception metadata generator.
Emit sorted runtime-function records and validate range/order/alignment. Keep the
example's unwind bytes adjacent to annotated machine code so changes are reviewed
together. Verify non-leaf frames and leaf exceptions against Microsoft's
[x64 exception-handling reference](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64).

Exit: TLS and exception directories reparse correctly, generated absolute TLS
addresses rebase exactly, and metadata is ready for runtime validation.

## 9. P6 — runnable examples and runtime acceptance

Implement `examples/pe_hello.rs`, `examples/pe_dll.rs`, and
`examples/pe_dll_load.rs` with explicit argument validation and clear failures.
Document each byte sequence with instruction boundaries, ABI effects, symbols,
and fixup offsets. Keep standard-library filesystem/argument handling in examples.
Use example `required-features = ["std"]`; give the Windows loader a harmless
non-Windows entry point so Linux all-target builds remain valid.

Hello must include the proposal's observable TLS flag check and dereferenced greeting
pointer. Implement both calling conventions; check the x64 call frame against the
[Microsoft ABI](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).
The DLL must export exactly `Add`, `GetGreeting`, and ordinal 3, use the declared
system ABI, and read its greeting through an absolute pointer slot. The loader reads
the greeting before unload and checks all results, including wrapping addition.

Add a Windows acceptance driver with explicit timeouts and cleanup:

1. Generate all four files on Linux from source, retaining file hashes and arguments.
2. Inspect with the existing pefile infrastructure or an independent PE tool; record
   discrepancies without treating a HexSpell round trip as an independent oracle.
3. Run each EXE on Windows. Find its dialog by process identity, verify the greeting,
   dismiss it, and require exit status zero. A missing TLS flag must produce the
   distinct failure code. Use a controlled negative variant to test that detection.
4. Run matching x86/x64 DLL loaders, resolve named/ordinal exports, verify values,
   and check `FreeLibrary` success. Do not invoke ordinal gaps.
5. For DLL relocation, reserve the preferred address range in the loader before
   `LoadLibraryW`; confirm the loaded module base differs and release the reservation.
6. For EXE relocation, use an architecture-matched debugger/controller that observes
   process creation and the actual mapped image base. Run an image with a deliberately
   unusable preferred range and intact relocations; verify on supported Windows
   versions that it loads elsewhere. If it fails to load, implement controlled
   address-conflict injection before image mapping instead of accepting a random
   ASLR observation. This harness is an early P6 feasibility gate, not a hidden
   assumption that reserving memory in the parent affects the child.
7. Verify the TLS callback reason/order under debugger instrumentation on both
   targets. For x64, use runtime unwind APIs to check lookup and unwinding for a
   controlled context in the generated non-leaf function, including relocated images.

Windows GUI checks need an interactive desktop; ordinary headless CI is insufficient.
Keep structural CI mandatory and runtime checks separately runnable with recorded OS,
architecture, preferred/actual bases, results, and diagnostics. Cross-compilation is
not execution. Do not declare milestone 3 complete while runtime gates are unverified.

## 10. P7 and P8 — generic resources

### P7: parser prerequisites

First add a named-entry regression with the name high bit set. Mask the name offset
before reading it, update the existing nonconforming fixture, and cover malformed
count/tag combinations without breaking intentional parser compatibility silently.
The metadata offset distinction is specified in the
[PE resource format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section).

Add checked raw UTF-16 access and complete payload-range access. Translating only
the starting RVA is insufficient: verify the entire extent is file-backed and does
not accidentally read an adjacent raw region. Handle external payload sections,
zero-length payloads, virtual tails, overflow, truncated names, cycles, and excessive
depth/work. Retain the existing decoded display strings while preserving original
units for editing. Apply limits before allocation or recursion.

### P8: model and serialization

Represent directory keys as numeric IDs or raw UTF-16 units, directory metadata
explicitly, and leaves as payload bytes plus code page/reserved metadata. Resolve
numeric-key width against the on-disk definition without truncating raw values into
the old `Option<u16>` convenience field. Preserve existing public types.

Implement path lookup, enumeration, insert, explicit replace, remove, and rename.
Validate destination collisions before changing the model. Support generic depths,
language keys, unknown types, and unknown payload bytes. A tree-owned structure can
prevent construction cycles, while import still validates hostile cyclic input.

Build one measured serializer shared by generation and editing: directories,
entry arrays, UTF-16 strings, leaf records, and aligned payloads. Canonicalize named
keys before IDs with deterministic ordering within each class. Check encoded offset
limits, counts, lengths, and final payload RVAs. Logical round trips preserve data
and metadata; they need not preserve the original byte ordering or padding.

Tests: named/ID/multilingual trees, unusual depths, unpaired surrogates, metadata,
unknown types, external/shared payloads, duplicates, rename collisions, large sizes,
malformed extents, deterministic serialization, and reparsed `Field` positions.
Add manifest/RCDATA to Hello using `set_resources` once this unit passes.

Exit: milestone 4 can import a valid resource tree losslessly at the model level,
modify it, serialize it, and parse every emitted payload on both targets.

## 11. P9 — transactional resource editing

Start with append as the conservative placement path; add in-place reuse only when
the caller/editor can prove exclusive ownership of every overwritten byte. A
resource-directory size is not an ownership proof. Shared payloads and unknown
references force append or a clear unsupported result.

Commit algorithm:

1. Read the source and edited model without mutation; validate all planned output.
2. Clone the original buffer once into a candidate and parse that candidate.
3. Preflight section insertion: header space, maximum occupied raw/virtual ends,
   all alignments, arithmetic, and file-offset references. Do not assume the final
   table entry has the greatest address. Reject unsupported overlapping layouts.
4. Serialize at the selected final RVA. Reuse insertion helpers only where their
   preconditions hold. Add narrow regression-backed fixes if header/raw movement
   exposes a helper defect. Never move existing section RVAs to make room.
5. Ensure the optional header actually contains the resource directory slot;
   grow it safely if supported, otherwise fail before committing. Do not mistake a
   synthesized absent-directory `Field` for writable storage.
6. Update the resource directory, affected summary values, and checksum. Preserve
   overlay ordering, certificate alignment, and tracked file-offset references
   using `FileOffsetFixups`; audit debug and COFF locations as well as section data.
7. Apply explicit signature policy. `PreserveBytes` retains certificate bytes and
   reports invalidation. Define `Strip` as clearing the security directory and
   removing only a verified certificate range; retain unrelated overlay bytes and
   translate affected offsets. Reject ambiguous overlap rather than deleting it.
8. Reparse and verify the resource model and preservation invariants. Swap the
   candidate into the caller's image only after every check succeeds. Return an
   edit report containing placement and signature outcome.

Tests: absent directory/resources; grow/shrink/add/remove/rename; insufficient header
slack; multiple edits; unsorted section layouts; external/shared payloads; overlay
sentinels; certificate policies; debug/COFF pointers; unchanged section RVAs; and
failure atomicity. Compare unrelated data by translated file ranges, not obsolete
absolute offsets after insertion. Verify source fields and bytes remain identical
after errors at preflight, emission, insertion, and reparse stages.

Exit: milestone 5 supports safe generic editing, including signed inputs with an
explicit reported policy, without depending on arbitrary embedded-RVA rewriting.

## 12. P10–P12 — typed resource codecs

Implement codecs on top of the owned model; none should maintain a second PE writer.

| Unit | Implementation | Required tests and Windows validation |
| --- | --- | --- |
| P10 manifest/RCDATA | Byte-preserving payload access; optional checked UTF-8 view, no XML parser | Opaque bytes survive; invalid UTF-8 errors; Windows reads selected language/type/name |
| P10 strings | Sixteen-slot blocks; checked ID-to-block/slot mapping; UTF-16 lengths and language-aware updates | Empty slots, boundaries, surrogate units, neighboring-slot preservation; Windows string lookup |
| P11 versions | Checked nested block parser/writer with alignment and type-dependent length units; preserve unknown children | Nested truncations, translations, text/binary values, unknown child data; Windows version queries |
| P12 icons | Checked ICO import/export; allocate unused icon IDs; update group references atomically | Multiple images, PNG/DIB payload preservation, shared IDs/languages, size failures; Windows icon loading |

For icons, remove an old image only after proving no remaining group references it.
Do not transcode bitmap data. For version blocks, define semantic preservation versus
byte preservation explicitly and keep uninterpreted child bodies intact. Add
`examples/pe_resources.rs` for editing and resource variants of Hello, then document
the runtime verification commands. Typed cursor/menu/dialog/bitmap support stays deferred.

## 13. Verification and documentation for every unit

Use focused tests during development; finish implementation units with the repository
checks. This checkout has no project flake, so the shared default shell is the
current development fallback (recheck if the repository gains a local environment).

```sh
nix develop --no-write-lock-file "path:$HOME/projects-caddy/nix-dev-shells/default" -c cargo fmt
nix develop --no-write-lock-file "path:$HOME/projects-caddy/nix-dev-shells/default" -c cargo clippy --all-targets -- -D warnings
nix develop --no-write-lock-file "path:$HOME/projects-caddy/nix-dev-shells/default" -c cargo test
nix develop --no-write-lock-file "path:$HOME/projects-caddy/nix-dev-shells/default" -c cargo clippy --all-features --all-targets -- -D warnings
nix develop --no-write-lock-file "path:$HOME/projects-caddy/nix-dev-shells/default" -c cargo test --all-features
nix develop --no-write-lock-file "path:$HOME/projects-caddy/nix-dev-shells/default" -c cargo test --no-default-features --features pe,elf,macho,common,pe,write --test no_std
```

Extend `tests/no_std.rs` with in-memory generation and resource editing as available.
Run new integration targets without default features where they use no file APIs.
Check the declared MSRV for new APIs. Avoid changing Cargo cache/wrapper configuration.

For each completed unit:

- Add tests for changed behavior and a previously failing test for every bugfix.
- Update `docs/guide.md` for usage; `docs/layout.md` only for actual field accessors;
  `docs/coverage.md` only for shipped support; README for the newly usable surface.
- Add user-relevant changelog entries in the repository's module/type ordering;
  mark breaking changes and bump semver if compatibility cannot be retained.
- Update proposal/plan status to distinguish implemented, structurally tested, and
  Windows-validated work. Include exact commands and results in the change description.
- Keep generated fixtures in memory or temporary files. If binaries are committed,
  record provenance in `tests/readme.md` and rebuild sources under `tests/source/`.
- Regenerate `tests/tests.toml` only when existing fixture expectations change;
  synthetic builder tests do not require the PE32-centric generator.

## 14. Completion checklist

- [x] P0–P1: coherent contracts and PE32/PE32+ generation with resolved layouts.
- [x] P2–P3: deterministic imports and named/ordinal exports with stable references.
- [x] P4–P5: checked fixups, relocation blocks, TLS, and example unwind metadata.
- [x] P6: all four generated binaries pass Windows behavior and forced-relocation checks.
- [x] P7–P8: resource prerequisites fixed; lossless model and shared serializer pass.
- [x] P9: edits are atomic, preserve existing RVAs/unrelated data, and report signature impact.
- [x] P10–P12: typed codecs and resource examples pass structural and Windows checks.
- [x] Default/no-std checks, public docs, changelog, and any fixture provenance are complete.

Forwarders, delay imports, CLR generation, signing, arbitrary compiler exception data,
resource compaction, a general linker/assembler, and a GUI remain outside this plan.
