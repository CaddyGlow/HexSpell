"""Benchmark preloaded PE buffers; emit the Rust runner's CSV schema."""

import argparse
import csv
import gc
import platform
import statistics
import sys
import time
from pathlib import Path

import pefile


def measure(data, scope, milliseconds, rounds):
    directory_names = [
        "IMPORT",
        "EXPORT",
        "RESOURCE",
        "TLS",
        "DEBUG",
        "LOAD_CONFIG",
        "BOUND_IMPORT",
        "DELAY_IMPORT",
        "EXCEPTION",
        "BASERELOC",
    ]
    directories = [
        pefile.DIRECTORY_ENTRY[f"IMAGE_DIRECTORY_ENTRY_{name}"]
        for name in directory_names
    ]

    def action():
        with pefile.PE(data=data, fast_load=scope != "default_parse") as image:
            if scope == "supported_directories":
                image.parse_data_directories(directories=directories)
            return len(image.sections)

    for _ in range(3):
        action()
    samples = []
    iterations = 0
    for _ in range(rounds):
        gc.collect()  # Before timing; normal GC remains enabled during the run.
        count = 0
        start = time.perf_counter_ns()
        while True:
            action()
            count += 1
            if time.perf_counter_ns() - start >= milliseconds * 1_000_000:
                break
        samples.append((time.perf_counter_ns() - start) // count)
        iterations += count
    return min(samples), int(statistics.median(samples)), max(samples), iterations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--milliseconds", type=int, default=100)
    parser.add_argument("--rounds", type=int, default=7)
    args = parser.parse_args()
    if args.milliseconds <= 0 or args.rounds <= 0:
        parser.error("duration and rounds must be positive")
    files = sorted(
        path
        for path in args.corpus.iterdir()
        if path.suffix.lower() in (".exe", ".dll")
    )
    if not files:
        parser.error("corpus has no .exe or .dll files")
    print(
        f"Python {platform.python_version()}; pefile {pefile.__version__}; {args.rounds} rounds x {args.milliseconds} ms; {len(files)} files",
        file=sys.stderr,
    )
    writer = csv.writer(sys.stdout)
    writer.writerow(
        [
            "file",
            "bytes",
            "format",
            "sections",
            "directories",
            "library",
            "scope",
            "min_ns",
            "median_ns",
            "max_ns",
            "iterations",
            "status",
        ]
    )
    failed = False
    for path in files:
        data = path.read_bytes()
        try:
            with pefile.PE(data=data, fast_load=True) as image:
                meta = [
                    path.name,
                    len(data),
                    "PE32+" if image.PE_TYPE == 0x20B else "PE32",
                    len(image.sections),
                    sum(
                        bool(d.VirtualAddress and d.Size)
                        for d in image.OPTIONAL_HEADER.DATA_DIRECTORY
                    ),
                ]
        except (pefile.PEFormatError, ValueError, OSError) as error:
            print(f"{path}: {error}", file=sys.stderr)
            writer.writerow(
                [
                    path.name,
                    len(data),
                    "unknown",
                    "",
                    "",
                    "pefile",
                    "metadata",
                    "",
                    "",
                    "",
                    "",
                    "error",
                ]
            )
            failed = True
            continue
        for scope in ("fast_headers", "default_parse", "supported_directories"):
            try:
                writer.writerow(
                    meta
                    + ["pefile", scope]
                    + list(measure(data, scope, args.milliseconds, args.rounds))
                    + ["ok"]
                )
            except (pefile.PEFormatError, ValueError, OSError) as error:
                print(f"{path} / {scope}: {error}", file=sys.stderr)
                writer.writerow(meta + ["pefile", scope, "", "", "", "", "error"])
                failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
