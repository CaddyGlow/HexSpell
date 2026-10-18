"""Build a corpus and run both benchmark programs sequentially, saving evidence."""

import argparse
import csv
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pefile
import tomllib


def capture(command, cwd):
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "output", type=Path, help="directory for corpus, CSV, metadata, and summary"
    )
    parser.add_argument(
        "--corpus", type=Path, help="use an existing corpus instead of generating one"
    )
    parser.add_argument("--extra", action="append", type=Path, default=[])
    parser.add_argument("--milliseconds", type=int, default=100)
    parser.add_argument("--rounds", type=int, default=7)
    args = parser.parse_args()
    if args.milliseconds <= 0 or args.rounds <= 0:
        parser.error("duration and rounds must be positive")
    if args.corpus and args.extra:
        parser.error("--extra is only for a newly generated corpus")
    root = Path(__file__).resolve().parents[2]
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    corpus = args.corpus.resolve() if args.corpus else args.output / "corpus"
    if not args.corpus:
        command = [
            sys.executable,
            str(root / "tools/pe-bench/build_corpus.py"),
            str(corpus),
        ]
        for path in args.extra:
            command += ["--extra", str(path.resolve())]
        subprocess.run(command, cwd=root, check=True)
    files = sorted(
        path for path in corpus.iterdir() if path.suffix.lower() in (".exe", ".dll")
    )
    if not files:
        parser.error("corpus is empty")
    manifest = root / "tools/pe-bench/Cargo.toml"
    # Compile before starting either timed program.
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "--manifest-path", str(manifest)],
        cwd=root,
        check=True,
    )
    rust_command = [
        "cargo",
        "run",
        "--release",
        "--locked",
        "--manifest-path",
        str(manifest),
        "--",
        str(corpus),
        str(args.milliseconds),
        str(args.rounds),
    ]
    python_command = [
        sys.executable,
        str(root / "tools/pe-bench/pefile_bench.py"),
        str(corpus),
        "--milliseconds",
        str(args.milliseconds),
        "--rounds",
        str(args.rounds),
    ]
    metadata = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_revision": capture(["git", "rev-parse", "HEAD"], root),
        "git_status": capture(["git", "status", "--short"], root),
        "hexspell_version": tomllib.loads((root / "Cargo.toml").read_text())["package"][
            "version"
        ],
        "rustc": capture(["rustc", "-Vv"], root),
        "python": platform.python_version(),
        "pefile": pefile.__version__,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": platform.processor(),
        "milliseconds_per_round": args.milliseconds,
        "rounds": args.rounds,
        "rust_command": rust_command,
        "python_command": python_command,
        "cargo_lock_sha256": hashlib.sha256(
            (manifest.parent / "Cargo.lock").read_bytes()
        ).hexdigest(),
        "corpus": [
            {
                "file": path.name,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in files
        ],
    }
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        metadata["cpu"] = next(
            (
                line.split(":", 1)[1].strip()
                for line in cpuinfo.read_text().splitlines()
                if line.startswith("model name")
            ),
            metadata["cpu"],
        )
    statuses = {}
    for label, command in [("rust", rust_command), ("python", python_command)]:
        print(f"Running {label} benchmarks...", flush=True)
        with (args.output / f"{label}.csv").open("w") as output:
            statuses[label] = subprocess.run(
                command, cwd=root, stdout=output, check=False
            ).returncode
    metadata["exit_statuses"] = statuses
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rows = []
    for label in ("rust", "python"):
        with (args.output / f"{label}.csv").open() as source:
            rows += list(csv.DictReader(source))
    summary = [
        "# PE parser benchmark",
        "",
        f"{len(files)} files; {args.rounds} rounds of {args.milliseconds} ms per scope; medians below in microseconds.",
        "",
        "Parsing scopes differ. HexSpell's owned scopes include the input copy; its borrowed view reads DOS/NT/COFF only, while the separate borrowed-all-fields scope decodes the optional header and iterates sections. object borrows headers and reads every section-header field. Goblin's default parser also processes directories. pefile fast_load reads headers/sections; its default and supported-directories modes do more work. Compare each scope explicitly; this is not a single equivalent-work ranking.",
        "",
        "File I/O, corpus generation, and process startup are excluded from timing. Python uses normal garbage collection with a collection before each timed round. min/max timings and iteration counts are retained in CSV. Run on an otherwise idle host for performance conclusions.",
        "",
        "| File | Bytes | Sections | Directories | Library | Scope | Median µs | Status |",
        "|---|---:|---:|---:|---|---|---:|---|",
    ]
    for row in rows:
        timing = f"{int(row['median_ns']) / 1000:.3f}" if row["median_ns"] else ""
        summary.append(
            f"| {row['file']} | {row['bytes']} | {row['sections']} | {row['directories']} | {row['library']} | {row['scope']} | {timing} | {row['status']} |"
        )
    summary += [
        "",
        "Reproduction details, versions, source revision, dirty working-tree status, hardware, commands, and corpus hashes are in metadata.json. Generated corpus provenance is in corpus/manifest.json (or the supplied corpus directory).",
        "",
    ]
    (args.output / "summary.md").write_text("\n".join(summary))
    print(f"Results: {args.output / 'summary.md'}")
    return int(any(statuses.values()) or any(row["status"] != "ok" for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
