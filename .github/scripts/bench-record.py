# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""Measure a glsec binary for the benchmark history (#875).

    bench-record.py BINARY INPUT OUT.jsonl --kind main|release --commit SHA
        --date ISO-DATE --input-version N [--runs N] [--go-bench FILE]

Scans INPUT with BINARY RUNS times from an empty directory, so no
.glsec.yml or ignore file is read, and appends one JSON record to OUT.jsonl.
It works for every release since v0.1.0: the flags that turn off the cache,
the repository config and the ignore files are passed only when the binary's
--help lists them. Exit status 2 (a scan error) fails the measurement.

--go-bench adds the medians of `go test -bench -benchmem` output, available
for commits since #843. Allocations don't depend on the machine; time does,
so each record also names the Go version and the CPU.
"""

import argparse
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time

OPTIONAL_FLAGS = ("no-cache", "no-repo-config", "no-ignores", "no-exit-codes")
GO_BENCH = re.compile(
    r"^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op"
    r"(?:.*?\s([\d.]+) B/op)?(?:.*?\s([\d.]+) allocs/op)?"
)


def run(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)


def flags_for(binary, cwd):
    out = run([binary, "--help"], cwd)
    text = out.stdout + out.stderr
    return [f"--{f}" for f in OPTIONAL_FLAGS if re.search(rf"(?<![\w-])--?{f}\b", text)]


def version_of(binary, cwd):
    out = run([binary, "--version"], cwd)
    m = re.search(r"\bv?(\d+\.\d+\.\d+\S*)", out.stdout + out.stderr)
    return m.group(1) if m else None


def rule_count(binary, cwd):
    out = run([binary, "list"], cwd)
    if out.returncode != 0:
        return None
    n = len(re.findall(r"(?m)^GL\d{3}\b", out.stdout))
    return n or None


def cli_times(binary, input_path, runs, cwd):
    args = [binary, *flags_for(binary, cwd), input_path]
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        out = run(args, cwd)
        elapsed = time.perf_counter() - start
        if out.returncode not in (0, 1):
            sys.exit(f"error: {' '.join(args)} exited {out.returncode}: {out.stderr.strip()[:300]}")
        times.append(round(elapsed * 1000, 1))
    return args[1:-1], times


def go_bench(path):
    runs = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = GO_BENCH.match(line)
            if m:
                values = [float(v) if v else None for v in m.group(2, 3, 4)]
                runs.setdefault(m.group(1), []).append(values)
    result = {}
    for name, rs in runs.items():
        med = []
        for i in range(3):
            vals = [r[i] for r in rs if r[i] is not None]
            med.append(statistics.median(vals) if vals else None)
        result[name] = {"ns_per_op": med[0], "bytes_per_op": med[1], "allocs_per_op": med[2], "runs": len(rs)}
    return result


def cpu_model():
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def go_version():
    try:
        return run(["go", "env", "GOVERSION"], None).stdout.strip() or None
    except OSError:
        return None


def main(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary")
    p.add_argument("input")
    p.add_argument("out")
    p.add_argument("--kind", choices=("main", "release"), required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--date", required=True, help="commit date, ISO 8601")
    p.add_argument("--input-version", type=int, required=True)
    p.add_argument("--runs", type=int, default=7)
    p.add_argument("--go-bench")
    a = p.parse_args(argv[1:])

    binary = os.path.abspath(a.binary)
    input_path = os.path.abspath(a.input)
    with tempfile.TemporaryDirectory() as empty:
        flags, times = cli_times(binary, input_path, a.runs, empty)
        record = {
            "schema": 1,
            "kind": a.kind,
            "commit": a.commit,
            "date": a.date,
            "version": version_of(binary, empty),
            "rules": rule_count(binary, empty),
            "input": os.path.splitext(os.path.basename(input_path))[0],
            "input_version": a.input_version,
            "cli": {"median_ms": statistics.median(times), "runs_ms": times, "flags": flags},
            "go_bench": go_bench(a.go_bench) if a.go_bench else None,
            "go_version": go_version(),
            "cpu": cpu_model(),
            "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    with open(a.out, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
