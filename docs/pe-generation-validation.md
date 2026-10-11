# PE generation validation

Validated on 2026-10-11. Implementation plan: [pe-generation-plan.md](pe-generation-plan.md).
Usage and feature migration: [guide.md](guide.md#features-and-migrating-to-20).

## Feature contract

`pe`, `elf`, `macho`, and `common` are independent and enabled by default, together
with `std`. `common` exposes `reloc`, `strings`, `validation`, and `write`; core
fields, errors, and byte utilities remain available independently. The opt-in
`write` feature enables construction and editing for enabled formats. Combine it
with `pe` for PE construction and resource editing; it does not imply a format.
It works without `std` using `alloc`.

The package version is 2.0.0 because consumers using `default-features = false`
must now explicitly enable the formats and helper interface they use.

## Automated checks

Run commands inside the shared Nix development shell:

```sh
nix develop --no-write-lock-file "path:$HOME/projects-caddy/nix-dev-shells/default"
```

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
cargo test --no-default-features --features pe,elf,macho,common,pe,write --test no_std
```

The test suites cover both PE classes, checked layout and fixups, stable imports,
named and ordinal exports, relocations, TLS, runtime functions, owned resources,
UTF-16 names, typed resource codecs, transactional editing, and signature impact.
Regression tests cover section placement with raw extents larger than virtual
extents, unsorted sections, overlays, and invalid alignment.
Additional review regressions cover truncated optional headers with declared
directory slots, growth of valid headers without directory slots, insertion
extent overflow without mutation, and high-RVA x86 named imports colliding with
the ordinal flag.

All 16 subsets of `pe`, `elf`, `macho`, and `common` are checked without default
features using strict Clippy for all targets and the full applicable test suite.
CI also checks the explicit no-std format configuration and the opt-in writer.

Independent inspection uses `pefile==2024.8.26`:

```sh
HEXSPELL_PEFILE_PYTHON=/path/to/python HEXSPELL_PE_CORPUS=/path/to/corpus cargo test --all-features --test pefile -- --ignored
python tests/scripts/inspect_generated_pe.py --arch x86 --kind exe hello-x86.exe
python tests/scripts/inspect_generated_pe.py --arch x64 --kind exe hello-x64.exe
python tests/scripts/inspect_generated_pe.py --arch x86 --kind dll demo-x86.dll
python tests/scripts/inspect_generated_pe.py --arch x64 --kind dll demo-x64.dll
```

The generated-image inspector verifies headers, alignments, file-backed ranges,
checksum, imports, writable IAT, TLS and relocation sites, runtime functions, and
exports. It rejects structural warnings; the zero-padding percentage heuristic is
expected for these small synthetic images.

Build the corpus with `python tools/pe-bench/build_corpus.py /path/to/corpus`.
The standalone fuzz harness also passes strict Clippy and its four smoke tests
with `--manifest-path fuzz/Cargo.toml --locked`.

## Native Windows acceptance

Passed on Windows 11 build 26200 in a disposable `win11-dev` VM:

- Both EXEs run TLS before entry, display the expected Hello dialog, and exit 0.
- Disabling the TLS callback causes exit 42, verifying the negative control.
- Both EXEs run when their preferred base is occupied; the harness verifies the
  actual image base differs and the preferred mapping is committed.
- Both DLLs load, expose named and ordinal exports, return the expected wrapping
  sum and greeting, unload, and work after forced relocation.
- The relocated x64 EXE passes `RtlLookupFunctionEntry` and synthetic
  `RtlVirtualUnwind` checks.
- Native resource APIs read manifests, RCDATA, strings, icons, fixed version
  information, description, and translation metadata from both generated EXEs.
- Edited EXEs expose string `Edited resource` and file version 2.0 while preserving
  manifest, RCDATA, icon, description, and translation. TLS, dialog execution,
  exit status, and x64 unwind checks continue to pass.

Harnesses: `tests/scripts/pe-runtime.ps1` and
`tests/scripts/pe-resource-runtime.ps1`. The Rust test loader requires the matching
Microsoft VC runtime in the guest; the generated PE examples do not require a CRT.
The owned VM was stopped after validation.

Local evidence and generated artifacts are retained under
`/data/cache/hexspell-pe-generation/`, including `windows-runtime.json`,
`windows-resources.json`, `windows-runtime-edited.json`, and
`windows-resources-edited.json`. These cache files are not repository fixtures.

| Artifact | SHA-256 |
| --- | --- |
| hello-x86.exe | `9af79b09eadfc0d1b26ce9f90e7f62d5c40aaad089cbceb037f6047989057c67` |
| hello-x64.exe | `4c16b41d1cfd71005c666969c89bd12d28b37d524f5899950db2dc48cae289b8` |
| demo-x86.dll | `166227404677e978aba6a4766edf8a4439772aa3ce36e61cdff94684ec4cb651` |
| demo-x64.dll | `32ab28db7ca74592bade2f3bc223b14c658301797ad3a446dd86b29b854e1426` |
| hello-edited-x86.exe | `4c73466d1ea593f0c028762b4852e867783541e7ea84187e5a9fe85aac7b5074` |
| hello-edited-x64.exe | `0ec0730b32f8169a09c6c4de6cba661be7faba32744fca3577a24e6d698037d0` |

## Scope limits

This is a checked PE image builder, not a general linker or compiler. Forwarders,
delay imports, CLR generation, signing, resource compaction, and compiler exception
data generation remain out of scope. Resource replacement appends a new resource
region and reports signature invalidation or stripping. Version block preservation
retains semantic unknown data rather than original padding bytes. Export ordinals
are restricted to 1–65535 to match the existing parser interface.
