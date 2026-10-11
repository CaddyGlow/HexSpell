# HexSpell fuzzing

This standalone honggfuzz package keeps fuzz dependencies outside the published
library. Harnesses are shared by instrumented runners, corpus replay, and tests.

| Target | Checks |
| --- | --- |
| `parse` | PE, ELF, Mach-O and FAT header views; owned/borrowed acceptance; lazy directories, names, symbols and relocations; indexed/linear PE RVA agreement; archive parsing. |
| `roundtrip` | Patch PE timestamps or ELF/Mach-O flags, reparse the value using file endianness, restore it, and require byte-for-byte equality (the selected thin slice for FAT input). |

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
```

Seeds reuse existing fixtures and their provenance in `tests/readme.md`; generation
also adds truncated prefixes and synthetic 32/64-bit, little/big-endian ELF, Mach-O, and FAT seeds. Keep minimized discovered regressions in descriptive
checked-in tests or fixtures, rather than committing generated corpora.

Install `honggfuzz` 0.5.62 if `cargo hfuzz` is unavailable. On Linux use a shell
with GCC, binutils, libunwind, and libbfd development libraries (the sibling
ms-compress shell supplies these). From `fuzz/`:

```sh
export HFUZZ_BUILD_ARGS="--locked"
HFUZZ_INPUT=corpus/parse HFUZZ_RUN_ARGS="-n 1 -t 5 -N 1000 --exit_upon_crash" cargo hfuzz run parse
HFUZZ_INPUT=corpus/roundtrip HFUZZ_RUN_ARGS="-n 1 -t 5 -N 1000 --exit_upon_crash" cargo hfuzz run roundtrip
```

Remove `-N 1000` for sustained campaigns. If instrumentation conflicts with a
compiler cache or hardening wrapper, use an instrumentation-compatible shell as
in `../ms-compress/fuzz/README.md`. Replay a saved crash without instrumentation:

```sh
cargo run --manifest-path fuzz/Cargo.toml --locked --bin replay -- parse path/to/crash.fuzz
```
