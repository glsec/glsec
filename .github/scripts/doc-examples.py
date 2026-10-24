# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""Write the YAML examples of docs/rules/*.md to a directory (#696).

Takes the blocks under "Trigger example(s)" and "Safe alternative(s)", the
same ones rules/docexamples_test.go runs the rules on, so CI can validate them
against the GitLab CI schema. A block preceded by an HTML comment starting
with "<!-- schema: skip" is left out; the comment says why.
"""

import pathlib
import sys

out = pathlib.Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
count = 0
for doc in sorted(pathlib.Path("docs/rules").glob("GL*.md")):
    lines = doc.read_text(encoding="utf-8").split("\n")
    checked = False
    previous = ""
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
            if checked and not previous.startswith("<!-- schema: skip"):
                block = lines[i + 1 : end]
                # A component template: the schema covers the pipeline after
                # the spec: header, not the header itself.
                if "---" in block:
                    block = block[block.index("---") + 1 :]
                name = f"{doc.stem}_L{i + 2}.yml"
                (out / name).write_text("\n".join(block) + "\n", encoding="utf-8")
                count += 1
            i = end
        if line.strip():
            previous = line.strip()
        i += 1
print(f"{count} examples written to {out}")
