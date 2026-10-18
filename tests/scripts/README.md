## Comparing with Python pefile

The optional integration suite checks values, absolute file offsets, and widths
against pefile 2024.8.26. Integer values are transported as strings to retain the
full unsigned 64-bit range. Normal cargo test needs no Python dependencies.

| Area | Verification |
|---|---|
| DOS, COFF, optional headers | Every modeled field, PE32/PE32+, split DOS reserved arrays, nonzero patch sentinels |
| Data directories / sections | All active directory entries and every section field, raw payloads, RVA mapping, section counts |
| Imports / exports | Descriptors, names, hints, ordinal imports, 32/64-bit thunks, named export rows, all export function slots |
| TLS / exceptions / debug | Every modeled record field, including distinct RVA/file-pointer sentinels |
| Load configuration | Every modeled base field in both layouts; distinct EditList/cookie sentinels, 96/112/320-byte versions |
| Hybrid load configuration | CHPE pointer value/offset/width in PE32 and PE32+ for ARMNT/ARM64/ARM64X |
| Bound/delay imports, resources, base relocations | Every modeled record field; nine patterned inputs at zero and nonzero offsets |
| COFF symbols, section relocations, line numbers, certificates, CLR | All modeled fields via explicit SDK schemas, as described below |
| Creation / editing | Constructed PE32/PE32+ images; add zero/small/aligned/unaligned/large sections; remove first/middle/last; rename; grow optional header; sync; patch; write/reload |
| Corpus edits | Header/section fields and imports/exports before and after edits; original section payloads, overlays, and debug targets retained |
| Checksums | Existing fixtures, large odd/even buffers, and all edited corpus images |

Native record expectations come from pefile's own format declarations, including
field widths from Python struct.calcsize. Five records absent from pefile's
native formats use visibly named SDK_* schemas with pefile.Structure:
IMAGE_SYMBOL, IMAGE_RELOCATION, IMAGE_LINENUMBER, WIN_CERTIFICATE, and
IMAGE_COR20_HEADER. Those checks are independent SDK-schema comparisons, not
claims that pefile itself supports those directory parsers. Sources:
[Microsoft PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[CLR header](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Diagnostics/Debug/struct.IMAGE_COR20_HEADER.html).

The legacy PE32+ reserved2 accessor exposes only EditList's low DWORD; the oracle
labels that projection explicitly. Hybrid code-range placeholders remain None.
The light CHPE metadata blob reader and Rich-header decoding lack native pefile
field-by-field oracles; their existing Rust tests remain in place. Malformed
extent rejection is tested in Rust because parsers can have different error
policies. Structural verification does not claim Windows execution or rebuilding
of arbitrary code/data references when removing middle sections.

From the repository root:

```sh
python3 -m venv /tmp/hexspell-pefile-venv
/tmp/hexspell-pefile-venv/bin/python -m pip install pefile==2024.8.26
/tmp/hexspell-pefile-venv/bin/python tools/pe-bench/build_corpus.py /tmp/hexspell-pe-corpus
HEXSPELL_PEFILE_PYTHON=/tmp/hexspell-pefile-venv/bin/python \
  HEXSPELL_PE_CORPUS=/tmp/hexspell-pe-corpus cargo test --test pefile -- --ignored
```

CI builds the corpus and runs the suite explicitly, then smoke-tests both
benchmark runners. HEXSPELL_PEFILE_PYTHON defaults to python3 when unset.
The corpus combines documented compiler-built fixtures and deterministic
synthetic images; every generated file has provenance and a SHA-256 hash in its
manifest. See [benchmark instructions](../../tools/pe-bench/README.md) for corpus
details, adding owned real-world files, and recording timing results.

## Comparing Mach-O chained fixups with LIEF

`tests/lief.rs` compares `MachO::chained_fixup_slots` with LIEF 1.0.0 for every
slice of the given files: import count, every bind (slot address, symbol,
addend) and every rebase (slot address, unslid target). LIEF does not expose
arm64e signing fields, so authenticated rebases are checked structurally:
instruction keys (IA/IB) must sign pointers into executable segments and data
keys (DA/DB) pointers elsewhere. Pass any thin or FAT Mach-O files, for example
binaries copied from a macOS system (Apple binaries are not committed):

```sh
python3 -m venv /tmp/hexspell-lief-venv
/tmp/hexspell-lief-venv/bin/python -m pip install lief==1.0.0
HEXSPELL_LIEF_PYTHON=/tmp/hexspell-lief-venv/bin/python \
  HEXSPELL_MACHO_FIXUP_FILES=/path/to/nc:/path/to/zsh \
  cargo test --test lief -- --ignored --nocapture
```

## Generated EXE and DLL acceptance

`inspect_generated_pe.py` independently checks the generation examples using
pefile: headers, alignments, checksum, section ranges, imports/IAT permissions,
TLS pointer widths and relocation sites, x64 runtime-function coverage, and the
three DLL exports. It prints hashes and preferred bases for recording results.

```sh
cargo run --features pe,write --example pe_hello -- x64 /tmp/hello-x64.exe
cargo run --features pe,write --example pe_dll -- x64 /tmp/demo-x64.dll
/tmp/hexspell-pefile-venv/bin/python tests/scripts/inspect_generated_pe.py --arch x64 --kind exe /tmp/hello-x64.exe
/tmp/hexspell-pefile-venv/bin/python tests/scripts/inspect_generated_pe.py --arch x64 --kind dll /tmp/demo-x64.dll
```

Repeat with `x86` for PE32. These checks are separate from Windows execution,
forced relocation, TLS callback ordering, and unwind-runtime verification.

For Windows runtime validation, build `pe_dll_load` with `--features pe,write` for
both `i686-pc-windows-msvc` and `x86_64-pc-windows-msvc`. The MSVC Rust standard
library may require Microsoft's x86/x64 Visual C++ runtime redistributables in the
test guest; the generated EXEs/DLLs themselves do not use the CRT.

Generate `hello-no-tls-ARCH.exe` using the Hello example's `--no-tls-callback`
argument and `hello-conflict-ARCH.exe` using `--conflicting-base`. Copy images and
architecture-matched loaders (`pe_dll_load-x86.exe`, `pe_dll_load-x64.exe`) into one
directory. Run on an interactive Windows desktop:

```powershell
.\tests\scripts\pe-runtime.ps1 -Directory C:\hexspell
.\tests\scripts\pe-resource-runtime.ps1 -Paths C:\hexspell\hello-x86.exe,C:\hexspell\hello-x64.exe
```

The runtime driver checks exports, exact-base reservation before DLL loading,
TLS-negative exit 42, normal/conflicting-base EXE dialogs and exit codes, and x64
runtime unwind APIs on a relocated mapping. The resource driver uses native
resource/version/icon APIs. Exercise actual resource edits too:

```sh
cargo run --features pe,write --example pe_resources -- hello-x64.exe edited-x64.exe preserve
```

```powershell
.\tests\scripts\pe-resource-runtime.ps1 -Paths C:\hexspell\edited-x64.exe -ExpectedString 'Edited resource' -ExpectedVersionMajor 2
```

Repeat the editing check for x86. The drivers print JSON with hashes/results for
recording validation evidence; no generated binaries need to be committed.

### ELF and Mach-O writer acceptance

Run `python3 tests/scripts/elf-macho-runtime.py /tmp/hexspell-elf-macho` from the
repository root in a Rust development shell. It generates ELF and Mach-O examples,
checks layouts independently using Python's standard library, invokes `readelf`
and optionally `llvm-readobj`, and runs Linux AMD64 ELF acceptance. The native C
loader checks constructors/finalizers, imports/exports, relocated pointers,
initialized/zero-fill data, independent TLS storage across threads and caller
unwind records. Static executable reruns follow append-only custom-data editing.

On macOS run:

```sh
python3 tests/scripts/macho-runtime.py /tmp/hexspell-macho --arch arm64
python3 tests/scripts/macho-runtime.py /tmp/hexspell-macho --arch x86_64
```

An arm64 host requires Rosetta for the x86-64 gate. The harness generates hello and
dylib examples, uses `otool`/`dyld_info` plus independent inspection, applies external
ad-hoc signing, verifies and reparses signed images, and calls native imports,
exports and rebased pointers. It also checks custom-data edits with re-signing and
selected-slice FAT rebuilding. Runtime metadata gates use `native-loader.c` for
constructor/terminator ordering, per-thread TLVs and supplied-CFI traversal through
frameless unwind probes. TLV dylibs
are pinned by dyld; their termination gate checks process-exit callbacks rather
than assuming that `dlclose` unloads the image. Reports record target architecture,
tool versions and individual passed gates. Structural checks never substitute for
native acceptance; see the [recorded matrix](../../docs/elf-macho-generation-validation.md).


### Signature-container interoperability

The native Mach-O script also exercises the dedicated reserve/write API with a
real Apple-signed Hello image, requires byte-for-byte identity, verifies the
signature and executes the result. `tests/macho_signatures.rs` supplies malformed
layout and rollback regressions without requiring macOS.

For PE, `pe_certificates` exercises owned certificate-table import, removal,
append and replacement. It performs no cryptographic operation; sign and verify
using `signcode-rs` or another Authenticode implementation:

```sh
cargo run --features pe,write --example pe_certificates -- roundtrip signed.exe roundtrip.exe
signcode verify roundtrip.exe --ca-file test-root.pem --ignore-cdp
```

See `docs/pe-generation-validation.md` and
`docs/elf-macho-generation-validation.md` for the recorded test-CA/native results.


### Linux appended-signature interoperability

`elf-signature-runtime.py` compiles a synthetic relocatable ELF object, signs it
using Linux `scripts/sign-file` with SHA-256 and SHA-512, compares HexSpell attachment
and round-trip output byte-for-byte, extracts/removes the trailer, and checks the
CMS signature using OpenSSL. OpenSSL's `-noverify` skips certificate-chain trust;
it still verifies the signature and content. This does not load a kernel module
or assert kernel trust. Requires Cargo, a C compiler, OpenSSL and `sign-file`:

```sh
python3 tests/scripts/elf-signature-runtime.py /tmp/hexspell-appended --sign-file /usr/lib/linux-kbuild-VERSION/scripts/sign-file
```

All generated objects, test keys and certificates stay in the output directory.
Pure Rust malformed-input, endian and alias tests are in `tests/elf_signatures.rs`.
