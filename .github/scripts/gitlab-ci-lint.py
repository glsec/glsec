# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""Send pipeline files to the GitLab CI Lint API on gitlab.com (#840).

    gitlab-ci-lint.py version            print "version=<major.minor>"
    gitlab-ci-lint.py lint CACHE FILE...  lint the files not cached yet

The JSON schema check catches structure only; GitLab's linter also rejects an
undefined stage, a needs: on a missing job or a file without a visible job.

GITLAB_LINT_TOKEN is a project access token of GITLAB_LINT_PROJECT. Without
it (pull requests from forks get no secrets) the script prints a notice and
exits 0; those files are linted on the push to main after the merge.

A file that passed leaves an empty file named after the sha256 of the GitLab
major.minor version and its content in CACHE, so it is sent again only when it
changes or GitLab ships a new release. Failures and network errors are never
cached. Requests stay below the burst limit of 100 a minute for a free plan
user and wait out a 429.
"""

import hashlib
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

API = "https://gitlab.com/api/v4"
INTERVAL = 0.75  # 80 requests a minute
RETRIES = 3


def request(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        API + path,
        data=data,
        method="POST" if data else "GET",
        headers={
            "PRIVATE-TOKEN": os.environ["GITLAB_LINT_TOKEN"],
            "Content-Type": "application/json",
        },
    )
    for attempt in range(RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as err:
            if err.code != 429 or attempt == RETRIES:
                raise
            time.sleep(int(err.headers.get("Retry-After", "60")))
    raise AssertionError("unreachable")


def one_line(s):
    return " ".join(str(s).split())


def gitlab_version():
    version = request("/version")["version"]
    return ".".join(version.split(".")[:2])


def lint(cache, files):
    project = os.environ["GITLAB_LINT_PROJECT"]
    version = gitlab_version()
    cache.mkdir(parents=True, exist_ok=True)
    failed, skipped, sent = [], [], 0
    for path in files:
        content = path.read_text(encoding="utf-8")
        key = hashlib.sha256(f"{version}\n{content}".encode()).hexdigest()
        if (cache / key).exists():
            continue
        if sent:
            time.sleep(INTERVAL)
        sent += 1
        try:
            result = request(f"/projects/{project}/ci/lint", {"content": content})
        except urllib.error.HTTPError as err:
            if err.code in (401, 403, 404):
                sys.exit(f"error: GitLab answered {err.code}; check GITLAB_LINT_TOKEN and GITLAB_LINT_PROJECT")
            skipped.append(path)
            print(f"warning: {path}: not linted: {one_line(err)}")
            continue
        except (urllib.error.URLError, TimeoutError, ValueError) as err:
            skipped.append(path)
            print(f"warning: {path}: not linted: {one_line(err)}")
            continue
        if result.get("valid"):
            (cache / key).touch()
            continue
        failed.append(path)
        for msg in result.get("errors") or ["rejected without an error message"]:
            print(f"error: {path}: {one_line(msg)}")
    print(
        f"GitLab {version}: {len(files)} files, {sent} sent, "
        f"{len(failed)} rejected, {len(skipped)} not linted"
    )
    return 1 if failed else 0


def main(argv):
    # The version line goes to $GITHUB_OUTPUT, everything else to stderr.
    if not os.environ.get("GITLAB_LINT_TOKEN") or not os.environ.get("GITLAB_LINT_PROJECT"):
        print("notice: GITLAB_LINT_TOKEN or GITLAB_LINT_PROJECT is not set, skipping GitLab CI lint", file=sys.stderr)
        if argv[1:2] == ["version"]:
            print("version=none")
        return 0
    if argv[1:2] == ["version"]:
        try:
            print(f"version={gitlab_version()}")
        except urllib.error.HTTPError as err:
            sys.exit(f"error: GitLab answered {err.code}; check GITLAB_LINT_TOKEN")
        except (urllib.error.URLError, TimeoutError, ValueError) as err:
            print(f"warning: GitLab version lookup failed, skipping GitLab CI lint: {one_line(err)}", file=sys.stderr)
            print("version=none")
        return 0
    if len(argv) < 4 or argv[1] != "lint":
        sys.exit(__doc__)
    try:
        return lint(pathlib.Path(argv[2]), [pathlib.Path(f) for f in sorted(argv[3:])])
    except urllib.error.HTTPError as err:
        sys.exit(f"error: GitLab answered {err.code}; check GITLAB_LINT_TOKEN and GITLAB_LINT_PROJECT")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
