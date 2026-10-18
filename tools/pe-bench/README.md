# PE verification and benchmarks

This standalone tool compares HexSpell with Goblin 0.10.7, object 0.40.0, and
Python pefile 2024.8.26. Its Cargo dependencies and lockfile are isolated from
HexSpell; this directory is excluded from the published library.

## Corpus

`build_corpus.py OUTPUT` copies the three documented PE fixtures and generates
twelve deterministic PE32/PE32+ images. Cases range from 1 KB to roughly 4 MB,
with 1–96 sections, up to 512 imports and 1024 exports, resources, TLS, debug
records, load configuration, base relocations, AMD64 exception records, and
large overlays. These synthetic images are parser inputs, not runnable programs.
The existing compiler-produced fixtures provide real executable layouts.

Every generated corpus includes a manifest with SHA-256 hashes, source
provenance, sizes, architectures, section counts, directory names, and import/
export counts. No additional binaries are checked into `tests/samples`.

Use `--extra /path/to/owned.exe` (repeatable) when generating a corpus to include
larger applications, DLLs, drivers, managed images, or packers from your own
environment. Their local source paths and hashes are recorded; adding them does
not grant redistribution rights. There is no automatic download of executables.

## Run

From the repository root, with Rust and Python available:

```sh
python3 -m venv /tmp/hexspell-pefile-venv
/tmp/hexspell-pefile-venv/bin/python -m pip install pefile==2024.8.26
/tmp/hexspell-pefile-venv/bin/python tools/pe-bench/run.py /tmp/hexspell-benchmark
```

On the shared development profile:

```sh
nix develop --no-write-lock-file path:$HOME/projects-caddy/nix-dev-shells/default \
  -c /tmp/hexspell-pefile-venv/bin/python tools/pe-bench/run.py /tmp/hexspell-benchmark
```

The runner builds in release mode, then runs Rust and Python sequentially. The
default is seven rounds of at least 100 ms for each file and parsing scope.
`--milliseconds 10 --rounds 3` is a smoke run, not performance evidence.
`--corpus PATH` uses an existing corpus. Parsers that reject a file produce an
error row and a failing exit status rather than disappearing from the results.

Outputs: `rust.csv`, `python.csv`, `summary.md`, `metadata.json`, and (unless
supplied separately) `corpus/manifest.json`. Metadata captures compiler and
parser versions, CPU/OS, Git revision, dirty-tree status, commands, lockfile hash,
and hashes of the exact input files.

## What the timings mean

Disk reads, compilation, corpus generation, and process startup are outside
timing. Input bytes are preloaded. Parsing and dropping the resulting objects
are included. Python's ordinary GC stays enabled. Three warmups precede each
scope, and the CSV records min/median/max ns per iteration and iteration counts.

| Parser/scope | Work and ownership |
|---|---|
| HexSpell borrowed headers | `PeHeaders::parse`: DOS/NT/COFF only; optional fields and sections remain unread |
| HexSpell borrowed all header fields and sections | Optional-header field decoding and section iteration, without copying the input buffer or collecting sections |
| HexSpell owned default | `PE::from_buffer`, including buffer clone, eager headers/sections; base relocations are lazy |
| HexSpell supported directories | Owned parse plus imports, exports, resources, TLS, debug, load config, bound/delay imports, and AMD64 exceptions |
| object | Borrowed `PeFile32`/`PeFile64` plus every section-header field, matching HexSpell's borrowed all-fields scope |
| Goblin default | Borrowed default `PE::parse`, including its default directory processing |
| pefile fast headers | `PE(data=..., fast_load=True)` |
| pefile default | `PE(data=..., fast_load=False)` |
| pefile supported directories | Fast headers plus the same directory categories requested for HexSpell |

The scopes expose different representations and perform different amounts of
work. They are useful comparisons of available APIs, not an equivalent-work
speed ranking. Run on an otherwise idle host before drawing performance
conclusions; use larger corpora and longer rounds for release decisions.

The generated corpus also feeds the differential edit tests. See
[verification instructions](../../tests/scripts/README.md).
