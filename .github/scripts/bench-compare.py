# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""Compare `go test -bench` output of a pull request's base and head (#872).

    bench-compare.py BASE.txt HEAD.txt

Prints a Markdown table of the medians (time, bytes and allocations per
operation) and appends it to $GITHUB_STEP_SUMMARY when that is set.

Exits 1 when a benchmark got much slower: its median time grew by more than
LIMIT and every head run was slower than every base run. Shared runners vary
by 10 to 30%, so a smaller change, or one where the runs overlap, is shown
but not enforced. Allocations don't depend on the machine; they are reported
for reading, not checked.
"""

import os
import re
import statistics
import sys

LIMIT = 0.5  # +50%

LINE = re.compile(
    r"^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op"
    r"(?:.*?\s([\d.]+) B/op)?(?:.*?\s([\d.]+) allocs/op)?"
)


def load(path):
    runs = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = LINE.match(line)
            if not m:
                continue
            ns, b, allocs = (float(v) if v else None for v in m.group(2, 3, 4))
            runs.setdefault(m.group(1), []).append((ns, b, allocs))
    return runs


def median(runs, i):
    values = [r[i] for r in runs if r[i] is not None]
    return statistics.median(values) if values else None


def change(old, new):
    if old is None or new is None or old == 0:
        return ""
    return f"{(new - old) / old:+.0%}"


def fmt_time(ns):
    return "" if ns is None else f"{ns / 1e6:,.0f} ms"


def fmt_bytes(b):
    return "" if b is None else f"{b / 1e6:,.1f} MB"


def fmt_count(n):
    return "" if n is None else f"{n:,.0f}"


def compare(base, head):
    """Return the Markdown report and the names of regressed benchmarks."""
    names = [n for n in head if n in base]
    if not names:
        return "No benchmark ran on both the base and the head.\n", []
    out = [
        "| Benchmark | Time base | Time head | | B/op base | B/op head | | allocs base | allocs head | |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    regressed = []
    for name in names:
        b, h = base[name], head[name]
        cells = []
        for i, fmt in ((0, fmt_time), (1, fmt_bytes), (2, fmt_count)):
            old, new = median(b, i), median(h, i)
            cells += [fmt(old), fmt(new), change(old, new)]
        old_t, new_t = median(b, 0), median(h, 0)
        slower = new_t > old_t * (1 + LIMIT) and min(r[0] for r in h) > max(r[0] for r in b)
        if slower:
            regressed.append(name)
        mark = " ❌" if slower else ""
        out.append(f"| `{name}`{mark} | " + " | ".join(cells) + " |")
    runs = min(len(base[n]) for n in names), min(len(head[n]) for n in names)
    out.append("")
    out.append(
        f"Medians of {runs[0]} base and {runs[1]} head runs on the same runner. "
        f"A benchmark fails when its median time grows by more than {LIMIT:.0%} "
        "and every head run is slower than every base run."
    )
    return "\n".join(out) + "\n", regressed


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    report, regressed = compare(load(argv[1]), load(argv[2]))
    report = "## Benchmarks: base vs head\n\n" + report
    if regressed:
        report += "\n**Slower:** " + ", ".join(f"`{n}`" for n in regressed) + "\n"
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(report)
    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
