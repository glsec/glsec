# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""Check a pull request's benchmarks for allocation regressions (#872, #880).

    bench-compare.py BASE.txt HEAD.txt

Reads `go test -bench -benchmem` output of the base and the head and fails
when a benchmark's median allocs/op grew by more than ALLOCS_LIMIT percent
(default 5) and by more than ALLOCS_MIN_DELTA allocations (default 1000).
Allocations hardly depend on the machine (the same code differs by a few dozen
between runs), so a rise past both is a change in the code. A new rule adds
about 1% on average; a regexp compiled once per script line adds about 16%.

Time is not checked: shared runners vary by 10 to 30% even within one job.
benchstat shows it in the job summary. This script adds the allocation table
to $GITHUB_STEP_SUMMARY when that is set.
"""

import os
import re
import statistics
import sys

LINE = re.compile(r"^(Benchmark\S+?)(?:-\d+)?\s+\d+\s.*?\s([\d.]+) allocs/op")


def load(path):
    runs = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = LINE.match(line)
            if m:
                runs.setdefault(m.group(1), []).append(float(m.group(2)))
    return {name: statistics.median(values) for name, values in runs.items()}


def compare(base, head, limit, min_delta):
    """Return the Markdown report and the regressed benchmarks."""
    names = [n for n in head if n in base]
    if not names:
        return "No benchmark with allocations ran on both the base and the head.\n", []
    out = ["| Benchmark | allocs/op base | allocs/op head | |", "|---|---:|---:|---:|"]
    regressed = []
    for name in names:
        old, new = base[name], head[name]
        change = f"{(new - old) / old:+.1%}" if old else ""
        bad = old > 0 and new - old > min_delta and (new - old) / old * 100 > limit
        if bad:
            regressed.append(f"{name}: {old:,.0f} -> {new:,.0f} ({change})")
        out.append(f"| `{name}`{' ❌' if bad else ''} | {old:,.0f} | {new:,.0f} | {change} |")
    out.append("")
    out.append(
        f"Medians over all runs. A benchmark fails when its allocations grow by more than "
        f"{limit:g}% and by more than {min_delta:,.0f}."
    )
    return "\n".join(out) + "\n", regressed


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    limit = float(os.environ.get("ALLOCS_LIMIT", "5"))
    min_delta = float(os.environ.get("ALLOCS_MIN_DELTA", "1000"))
    report, regressed = compare(load(argv[1]), load(argv[2]), limit, min_delta)
    report = "## Allocations: base vs head\n\n" + report
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(report)
    for r in regressed:
        print(f"::error::{r}, limit {limit:g}% and {min_delta:,.0f} allocations")
    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
