# HexSpell fuzzing

This standalone honggfuzz package keeps fuzz dependencies outside the published
library. Harnesses are shared by instrumented runners, corpus replay, and tests.

| Target | Checks |
| --- | --- |
| `parse` | PE, ELF, Mach-O and FAT header views; owned/borrowed acceptance; lazy directories, names, symbols and relocations; signature commands/payloads, owned PE certificate serialization and ELF trailers; indexed/linear PE RVA agreement; archive parsing. |
| `roundtrip` | Patch PE timestamps or ELF/Mach-O flags, reparse the value using file endianness, restore it, and require byte-for-byte equality (the selected thin slice for FAT input). |
| `signatures` | PE certificate copy/serialize/append/replace/remove; Mach-O signature read/reserve/reuse/resize/write/remove; ELF trailer read/set/replace/remove. Rejections preserve buffers; successful edits preserve records, signed prefixes and bytes outside the blob. |
| `generation` | Bounded builders, runtime metadata and custom-payload edits, plus successful signature editing on generated PE32/PE32+, x86-64/arm64 Mach-O and stacked ELF trailers in both classes and byte orders. |

Inputs are ordinary executable bytes, capped at 1 MiB. Streamed tables are
visited up to 4096 entries and FAT inputs up to 32 slices. Eager lazy parsers
still process whole tables: run campaigns with process memory/time limits.
Malformed input may return errors but must not panic. Consistency checks are
not independent format oracles; the existing fixtures and pefile tests provide
separate compatibility checks. Structural editing is not covered by this initial
roundtrip target.

From the repository root in a Rust development shell:

```sh
cargo test --manifest-path fuzz/Cargo.toml --locked
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings
cargo run --manifest-path fuzz/Cargo.toml --locked --bin seed-executables -- fuzz/corpus
cargo run --manifest-path fuzz/Cargo.toml --locked --bin replay -- parse tests/samples/sample1.exe
cargo run --manifest-path fuzz/Cargo.toml --locked --bin replay -- signatures fuzz/corpus/signatures/signature-pe64-records
```

Seeds reuse existing fixtures and their provenance in `tests/readme.md`; generation
also adds truncated prefixes and synthetic 32/64-bit, little/big-endian ELF,
Mach-O, and FAT seeds. Signature seeds are copied into `parse`, `roundtrip` and
`signatures` corpora. They are deterministic builder/header outputs with opaque
payloads; no external signing tools or private keys are needed.

| Signature seeds | Cases |
| --- | --- |
| PE32 and PE32+ | Unsigned images, multiple records, unknown revision/type and nonzero padding, overlay preservation, malformed/overflowing lengths, unaligned or inconsistent directories, missing slots, post-table overlays and section/relocation/debug/COFF aliases. |
| Mach-O x86-64 and arm64 | Unsigned/signed images, entry points in command padding, occupied padding, duplicate/short commands, overflowing or unaligned blobs, empty reservations, header/section/mapping aliases, post-blob overlays and unsupported commands. |
| Mach-O readers | 32/64-bit headers in both byte orders with bounded signature blobs. |
| ELF32 and ELF64 in both byte orders | Single/stacked trailers, malformed metadata and lengths, partial markers, truncated metadata, and header/section/program/header-table aliases. |

Smoke tests replay every signature seed through all three file targets, then
mutate/truncate the seeds. The signature harness also deliberately retains stale
PE directory fields across buffer-only edits before appending; generated inputs
exercise all 256 selector values. Payloads and new signature reservations are
capped at 256 bytes (257 for a resize probe).

Keep minimized discovered regressions in descriptive
checked-in tests or fixtures, rather than committing generated corpora.

Install `honggfuzz` 0.5.62 if `cargo hfuzz` is unavailable. On Linux use a shell
with GCC, binutils, libunwind, and libbfd development libraries (the sibling
ms-compress shell supplies these). From `fuzz/`:

```sh
export HFUZZ_BUILD_ARGS="--locked"
HFUZZ_INPUT=corpus/parse HFUZZ_RUN_ARGS="-n 1 -t 5 -N 1000 --exit_upon_crash" cargo hfuzz run parse
HFUZZ_INPUT=corpus/roundtrip HFUZZ_RUN_ARGS="-n 1 -t 5 -N 1000 --exit_upon_crash" cargo hfuzz run roundtrip
HFUZZ_INPUT=corpus/signatures HFUZZ_RUN_ARGS="-n 1 -t 5 -N 1000 --exit_upon_crash" cargo hfuzz run signatures
```

Remove `-N 1000` for sustained campaigns. If instrumentation conflicts with a
compiler cache or hardening wrapper, use an instrumentation-compatible shell as
in `../ms-compress/fuzz/README.md`. Replay a saved crash without instrumentation:

```sh
cargo run --manifest-path fuzz/Cargo.toml --locked --bin replay -- parse path/to/crash.fuzz
```

For the shared projects-caddy shell, the following invocation supplies the native
development headers and disables compiler caching/incremental compilation only
for the instrumented run (from `fuzz/`):

```sh
nix develop --no-write-lock-file "path:$HOME/projects-caddy/nix-dev-shells/default" \
  -c nix-shell -p binutils-unwrapped libunwind --run \
  'env RUSTC_WRAPPER= CARGO_INCREMENTAL=0 CC=gcc NIX_HARDENING_ENABLE= \
    HFUZZ_INPUT=corpus/signatures HFUZZ_BUILD_ARGS=--locked \
    HFUZZ_RUN_ARGS="-n 1 -t 5 -N 10000 --exit_upon_crash" cargo hfuzz run signatures'
```

The `generation` target exercises bounded ELF/Mach-O owned builders, ELF custom
payload growth/addition and Mach-O dynamic imports, chained pointers, lifecycle
arrays and initialized TLVs. Payloads are capped at 256 bytes, alignments are
bounded, and rejected capacity edits must preserve the original buffer. Ordinary
unit tests additionally cover bounded loader strings, owned notes, signature
stripping, malformed offset ranges and FAT rebuilding. These are smoke tests;
they do not claim native runtime coverage or sustained fuzz-campaign results.
Run it with `cargo hfuzz run generation` from this directory, or replay with
`cargo run --bin replay -- generation PATH`. The smoke tests cover all 256
selector values without invoking external tools or executing generated code.
