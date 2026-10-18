# ELF and Mach-O generation validation

Implementation and acceptance status, 2026-10-11. The
[plan](elf-macho-generation-plan.md) defines the scoped milestone profiles;
structural tests and native runtime gates are recorded separately below.
No generated binary fixtures are committed by this work.

## Implemented profiles

| Milestone | Coverage | Acceptance |
| --- | --- | --- |
| C0 | Opt-in features, dependency-free `no_std + alloc`, owned specifications, foreign-handle/error contracts and explicit deployment profiles | Unit tests, feature checks, MSRV and bare-metal checks |
| E1 | Linux AMD64 ELF64 little-endian placement plus explicit-layout ELF32/64 serialization in either byte order with extended-count encodings | Static and sectionless PIE execution; independent inspection |
| E2 | Static symbols and checked absolute64/32 and next-field-origin PC-relative32 writes | Foreign handles, overlaps, range overflow and layout tests |
| E3 | Explicit interpreter, eager imports, versioned imports/exports, visibility, SysV hash, SONAME/RUNPATH and RELA | Native imports/exports, dlvsym versions, symbol interposition, initialized/zero-fill data and relocated pointers at distinct load addresses |
| E4 | Transactional nonallocated data replace/grow/add/remove, rename, owned notes, bounded interpreter/NEEDED/SONAME/RUNPATH and explicit build-ID consequences | Reference/alias rejection, ELF32 big-endian edits, malformed extents, dropped/failed sessions and native static rerun |
| E5 | Shared-object lifecycle arrays, AMD64 general-dynamic TLS, caller `zR` CIE/FDE integration and GNU EH-frame index | Native constructor/finalizer order, per-thread storage and unwind traversal |
| M1 | Thin 64-bit little-endian x86-64/arm64 executable/dylib, explicit macOS target, sections/symbols/entry, zero-fill and layouts | Unit tests and independent inspection for both targets |
| M2 | macOS 13+ dyld imports/ASCII exports, stable dylib ordinals, RPATH, link-edit tables and PTR64_OFFSET chained binding/rebasing | Structural decoding, `dyld_info` inspection and native linkage gates |
| M3 | External ad-hoc signing, verification and reparsing of hello and dylib images | Native architecture-specific results recorded below |
| M4 | Checked custom-data replace/grow/add, bounded dylib/RPATH strings, explicit supported signature stripping and FAT resizing | Atomic failure/reference inventory tests; native re-sign/rerun and FAT gates recorded below |
| M5 | Lifecycle APIs, one initialized Apple TLV template/descriptor and caller EH-frame integration | Native architecture-specific runtime gates recorded below |
| C1 | Examples, CI feature/MSRV/bare-metal checks, independent inspectors, bounded generation/edit fuzz smoke tests and reproducible native harnesses | Exact session results recorded below |

## Profile limits

The runnable `ElfBuilder` profile targets Linux AMD64 ELF64 little endian.
`elf::build::layout::serialize_layout` also serializes explicit structural ELF32/64
layouts in either byte order and supports extended counts and section-name indices;
it does not establish an executable ABI or synthesize linkage. ELF editing supports
existing ELF32/64 images in either byte order. Mach-O32, big-endian Mach-O, arm64e,
object-file linking, PLT/lazy binding, IFUNC, copy/packed
relocations and additional TLS models are unsupported. ELF lifecycle arrays target
shared objects; PIE startup/termination needs a caller CRT. The ELF unwind profile
accepts caller CFI with one version-1 `zR` CIE and PC-relative signed four-byte FDE
pointers; personalities, LSDA and exception-handler synthesis are excluded.

Mach-O dyld output targets macOS 13+ and uses `DYLD_CHAINED_PTR_64_OFFSET` for
ordinary x86-64/arm64 pointers. Legacy runtime bind/rebase encoders, authenticated
arm64e pointers, non-ASCII export names, branch veneers, general compact-unwind
synthesis and additional TLV models are excluded. Without `enable_dyld`, build-time
VA fixups provide structural output without a runtime rebasing claim. Output is
unsigned; external signing remains required by the tested native workflow.

Editing preserves existing mapped VAs and rejects unknown affected references.
ELF custom growth is append-only, with power-of-two alignment up to 4096 bytes;
section removal preserves indices. Loader-owned notes and dynamic string growth
are rejected. Shared/suffix string aliases and version-table string consumers
reject bounded dynamic string edits. Build-ID removal neutralizes GNU note
identity without regenerating an ID. Mach-O custom addition requires verified
header slack and a placement before any `__LINKEDIT`. Existing linked images must
reserve `__CUSTOM` at construction. Custom growth consumes verified segment padding
or its zero file gap first, extending file size within existing virtual capacity.
It relocates only a final custom segment without virtual overlap. Supported
signature stripping truncates a final owned `__LINKEDIT` signature and shrinks the
segment file/virtual extents; unsupported layouts reject
edits. FAT rebuilding preserves every other thin slice and CPU/subtype/alignment
metadata while canonicalizing container offsets, width, byte order and padding.

## Reproduction

Use the project's development shell, then:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
cargo clippy --no-default-features --features elf,write --all-targets -- -D warnings
cargo test --no-default-features --features elf,write
cargo clippy --no-default-features --features macho,write --all-targets -- -D warnings
cargo test --no-default-features --features macho,write
cargo check --no-default-features --features pe,elf,macho,write --target thumbv7em-none-eabi
cargo clippy --manifest-path fuzz/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path fuzz/Cargo.toml --locked
python3 tests/scripts/elf-macho-runtime.py /tmp/hexspell-elf-macho
# On macOS; x86-64 on arm64 requires Rosetta:
python3 tests/scripts/macho-runtime.py /tmp/hexspell-macho --arch arm64
python3 tests/scripts/macho-runtime.py /tmp/hexspell-macho --arch x86_64
```

MSRV validation uses Rust/Cargo 1.88 with `cargo check --lib --all-features --locked`;
dev dependencies are excluded. Default features and existing `pe,write` regressions
are exercised separately. The bare-metal target needs its Rust standard libraries
installed; CI installs `thumbv7em-none-eabi` explicitly.

Python inspectors use the standard library and validate header counts, segment
extents/permissions, entry placement and tables independently. Linux acceptance
also uses GNU `readelf` and optional LLVM `llvm-readobj`. macOS acceptance uses
`otool`, `dyld_info`, external `codesign`, reparsing and a native C loader. Reports
record tool versions and individual gates. Ordinary Rust tests do not execute
generated machine code. Fuzz smoke tests bound payloads and alignments and do not
claim sustained fuzz-campaign or native execution coverage.

## Recorded session results

On x86-64 Linux, Rust/Cargo 1.99.0, GNU readelf 2.46 and LLVM 21.1.8:

- Static ELF hello and append-grown custom-data edited executable execute equally.
- PIE imports libc `write`, with section headers present and omitted.
- Shared objects call exported `answer` and imported `getpid`, resolve an owned
  function pointer at distinct load addresses, and preserve initialized/zero-fill
  storage.
- The native C loader verifies constructor/finalizer ordering, per-thread
  general-dynamic TLS and caller-supplied DWARF unwind traversal on original,
  edited and sectionless shared images. `dlvsym` resolves the declared version;
  interposition changes the exported pointer call to the overriding result 99 and
  invokes overriding constructors/finalizers in orders 12/21.
- Independent inspection accepts x86-64 and arm64 Mach-O examples.
- Focused transactional editing tests cover ELF growth/addition/removal, bounded
  strings, notes/build-ID policies, big-endian ELF32, signature stripping,
  checked malformed extents, live chained bind/rebase nodes (including segment
  padding), malformed chain traversal, legacy runtime-write rejection and selected
  FAT-slice growth. Aliased chained names/page tables are bounded, with an allocator
  regression covering the 12 KiB input that previously expanded to 8 MiB of names.
- Rust/Cargo 1.88 library compilation passed using an explicitly verified 1.88
  compiler. The combined `pe,elf,macho,write` no-default-feature
  clippy/test suite passed, as did all three writers on `thumbv7em-none-eabi`
  with Rust 1.99.0 and the installed bare-metal target. Default and all-feature
  formatting, all-target clippy with warnings denied, and full tests passed.
  Independent no-default `elf,write` and `macho,write` clippy/test suites passed.
  Fuzz clippy and five bounded smoke tests passed.

On macOS 26.6.2 (25G83), Apple clang 17.0.0 (clang-1700.4.4.1), SDK 26.1 and
Rust 1.98.0, the macOS 13.0 deployment profile passed all seven native gates for
arm64 and x86-64. The x86-64 images ran through Rosetta 2 on the arm64 host:

- Imported hello execution after ad-hoc signing, strict verification and reparsing.
- Dylib exports/imports, chained pointer rebasing and initialized/zero-fill data.
- Constructor ordering, independent per-thread TLVs, supplied DWARF CFI traversal
  through frameless functions and generated libSystem termination registration
  with reverse-order process-exit
  callbacks. TLV images remain pinned by dyld; `dlclose` is not an unload oracle.
- Edited/re-signed dylib and executable reruns with existing VAs preserved.
- FAT selected-slice rebuilding, untouched other thin bytes and extracted-image
  re-signing/native runtime checks.
- Independent `otool`/`dyld_info` inspection alongside clang-linked references.

The harness writes architecture-specific `acceptance.json`, `otool` and dyld reports
under its requested output directory. This session's reports are saved locally in
`/data/cache/hexspell-native-acceptance/{arm64,x86_64}/acceptance.json`.
The review-fix rerun also passed all seven gates on both architectures, with reports
in `/data/cache/hexspell-review-fixes-native/{arm64,x86_64}/acceptance.json`.
macOS 13.0 is the emitted deployment minimum;
these native results were collected on macOS 26.6.2, not on a macOS 13 host.

Native tests discovered and now cover program-header ordering, GNU EH-frame index
semantics, dyld chained-fixup/export alignment, UUID requirements and platform
lifecycle dispatch. These gates are distinct from successful Linux parsing.

The ELF placement rules follow the [generic ABI program-loading specification](https://gabi.xinuos.com/elf/07-pheader.html).
Mach-O command layouts follow Apple's [loader definitions](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/EXTERNAL_HEADERS/mach-o/loader.h),
and chained pointer layouts follow Apple's [fixup definitions](https://raw.githubusercontent.com/apple-oss-distributions/dyld/main/include/mach-o/fixup-chains.h).


## Embedded-signature container API acceptance

Validated on 2026-10-12 using the existing arm64 macOS host, with native arm64 and
x86-64 under Rosetta 2. `macho-runtime.py` now includes
`signature_container_roundtrip`: reuse the final signature reservation, reinstall
its original opaque blob, require byte-for-byte identity, verify using
`codesign --verify --strict`, then execute the Hello image. All eight acceptance
gates passed for each architecture. Equal-size reservations preserve Apple's
segment rounding, including the 16 KiB rounding observed on x86-64 outputs.
Changing capacity requires a new digest; cryptographic signing is external.

```sh
cargo run --features macho,write --example macho_validate -- signature-roundtrip SIGNED OUTPUT
codesign --verify --strict OUTPUT
```

`tests/macho_signatures.rs` covers new reservations, fixed-size installation,
replacement/removal, signed-prefix preservation, external segment rounding,
unknown commands, padding/section/segment aliases, duplicate commands, malformed
extents, overflow and rollback. APIs pass `no_std + alloc` and Rust 1.88 checks.


## Linux appended-signature acceptance

Validated on 2026-10-12 with upstream Linux v6.12 `scripts/sign-file` (compiled
locally with OpenSSL) and a synthetic compiler-generated relocatable ELF object.
The `elf-signature-runtime.py` harness passed for SHA-256 and SHA-512:

- HexSpell attachment from the oracle's detached PKCS#7 was byte-for-byte identical
  to the complete `sign-file` output, including the metadata and EOF marker.
- Removing and reattaching the signature preserved the complete file exactly.
- Extraction/removal recovered the original unsigned object byte-for-byte.
- OpenSSL CMS verified both detached signatures over the recovered prefix.
  `-noverify` bypassed certificate-chain trust, not signature/content checking.

No kernel module was loaded; this validates the container and CMS interoperability,
not module ABI compatibility, Secure Boot enrollment or kernel trust policy. Test
keys, objects and certificates were generated outside the repository. The oracle
sources were not vendored ([upstream v6.12 sign-file](https://github.com/torvalds/linux/blob/v6.12/scripts/sign-file.c)).

```sh
python3 tests/scripts/elf-signature-runtime.py /tmp/hexspell-appended --sign-file /path/to/scripts/sign-file
```

Rust tests cover ELF32/64 in both byte orders, executable/relocatable headers,
NOBITS ranges, overlays, stacked trailers, metadata offsets, network-order lengths,
malformed trailers, aliases into sections/programs/header tables and rollback.
Default/all-feature tests, warning-free Clippy, ELF read-only and ELF writer feature
checks, fuzz smoke tests, embedded `no_std + alloc`, and Rust 1.88 checks passed.
