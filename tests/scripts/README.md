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
