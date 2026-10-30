# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""List the keyword paths of GitLab's CI JSON schema (#931).

    gitlab-ci-keywords.py SCHEMA > keywords.txt

SCHEMA is GitLab's editor schema (app/assets/javascripts/editor/schema/ci.json
in gitlab-org/gitlab). One path per line, sorted: top-level keys as they are
(`workflow.rules[].if`), job keys under `job.` (`job.artifacts.reports.dotenv`),
`[]` for list items and `*` for keys the user names (`job.id_tokens.*.aud`).
The check-gitlab-ci-schema workflow compares the output with the reviewed
snapshot in .github/gitlab-ci-keywords.txt.

The schema is downloaded, so it is only read as data: a path is kept only if
every key in it looks like a GitLab keyword.
"""

import json
import re
import sys

MAX_DEPTH = 5
KEY = re.compile(r"^[a-z_][a-z0-9_]*$")
JOB_DEFINITIONS = {"job", "job_template"}


def keyword_paths(schema):
    definitions = schema.get("definitions", {})
    paths = set()

    def walk(node, path, depth, refs):
        if not isinstance(node, dict) or depth > MAX_DEPTH:
            return
        ref = node.get("$ref", "")
        if ref.startswith("#/definitions/"):
            name = ref.removeprefix("#/definitions/")
            # A top-level key that is a job (pages:) would list every job
            # keyword again; they are under job. already.
            if name in JOB_DEFINITIONS and path != "job":
                return
            if name not in refs:
                walk(definitions.get(name), path, depth, refs | {name})
        for combinator in ("allOf", "anyOf", "oneOf"):
            for sub in node.get(combinator, []):
                walk(sub, path, depth, refs)
        for key, sub in node.get("properties", {}).items():
            if not KEY.match(key):
                continue
            child = f"{path}.{key}" if path else key
            paths.add(child)
            walk(sub, child, depth + 1, refs)
        extra = node.get("additionalProperties")
        if path and isinstance(extra, dict) and extra:
            walk(extra, f"{path}.*", depth + 1, refs)
        for sub in node.get("patternProperties", {}).values():
            walk(sub, f"{path}.*", depth + 1, refs)
        items = node.get("items")
        if isinstance(items, dict):
            walk(items, f"{path}[]", depth + 1, refs)

    root = {k: v for k, v in schema.items() if k in ("properties",)}
    walk(root, "", 0, frozenset())
    walk(schema.get("additionalProperties"), "job", 0, frozenset())
    return sorted(paths)


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    with open(argv[1], encoding="utf-8") as f:
        schema = json.load(f)
    paths = keyword_paths(schema)
    if not any(p.startswith("job.") for p in paths):
        sys.exit("error: no job keywords found; has the schema layout changed?")
    for p in paths:
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
