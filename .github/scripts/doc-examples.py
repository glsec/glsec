# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""Write the YAML examples of docs/rules/*.md to a directory (#696).

Takes the blocks under "Trigger example(s)" and "Safe alternative(s)", the
same ones rules/docexamples_test.go runs the rules on, so CI can validate them.

The second argument picks the check, "schema" (default) or "lint" (#840). A
block preceded by an HTML comment starting with "<!-- schema: skip" or
"<!-- lint: skip" is left out of that check; the comment says why. For the
schema check a component template is cut to the pipeline after its spec:
header; GitLab's linter reads the whole file.
"""

import pathlib
import sys

out = pathlib.Path(sys.argv[1])
check = sys.argv[2] if len(sys.argv) > 2 else "schema"
if check not in ("schema", "lint"):
    sys.exit(f"unknown check {check!r}, want schema or lint")
marker = f"<!-- {check}: skip"
out.mkdir(parents=True, exist_ok=True)
count = 0
for doc in sorted(pathlib.Path("docs/rules").glob("GL*.md")):
    lines = doc.read_text(encoding="utf-8").split("\n")
    checked = False
    comments = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("## "):
            heading = line[3:].lower()
            checked = heading.startswith(("trigger example", "safe alternative"))
        elif line in ("```yaml", "```yml"):
            end = i + 1
            while not lines[end].startswith("```"):
                end += 1
            if checked and not any(c.startswith(marker) for c in comments):
                block = lines[i + 1 : end]
                if check == "schema" and "---" in block:
                    block = block[block.index("---") + 1 :]
                name = f"{doc.stem}_L{i + 2}.yml"
                (out / name).write_text("\n".join(block) + "\n", encoding="utf-8")
                count += 1
            i = end
        # The comment lines directly above a block, so a block can carry both
        # a schema and a lint marker.
        stripped = line.strip()
        if stripped.startswith("<!--"):
            comments.append(stripped)
        elif stripped:
            comments = []
        i += 1
print(f"{count} examples written to {out}")
