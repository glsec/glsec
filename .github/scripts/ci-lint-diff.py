# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0
"""Differential run: pipelines GitLab accepts against what glsec can scan (#895).

    ci-lint-diff.py GLSEC OUT FILE...

Sends each pipeline file to the GitLab CI Lint API and through
`GLSEC --no-cache --no-repo-config --format json`, then sorts the files into
four groups. The one that matters is "GitLab accepts, glsec exits 2": a glsec
parser bug. Run it by hand before a release, not in CI: it needs the network
and the GITLAB_LINT_TOKEN / GITLAB_LINT_PROJECT pair of gitlab-ci-lint.py.

GitLab takes seconds per file when it resolves includes, so WORKERS files are
linted at once; a shared limiter keeps all of them at 80 requests a minute.

OUT keeps lint.jsonl (one GitLab answer per content hash, so a rerun only sends
new files) and results.jsonl (one line per file). Files with an include: that
GitLab rejects are counted apart: the lint project can't resolve their
includes, so the rejection says nothing about the file.
"""

import hashlib
import http.client
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

API = "https://gitlab.com/api/v4"
INTERVAL = 0.75  # 80 requests a minute in all, below the burst limit
WORKERS = 5


class Limiter:
    def __init__(self, interval):
        self.interval, self.next, self.lock = interval, 0.0, threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            start = max(now, self.next)
            self.next = start + self.interval
        time.sleep(start - now)


def lint(content, limiter):
    req = urllib.request.Request(
        f"{API}/projects/{os.environ['GITLAB_LINT_PROJECT']}/ci/lint",
        data=json.dumps({"content": content}).encode(),
        headers={"PRIVATE-TOKEN": os.environ["GITLAB_LINT_TOKEN"], "Content-Type": "application/json"},
    )
    for attempt in range(5):
        limiter.wait()
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                r = json.load(resp)
                return {"valid": bool(r.get("valid")), "errors": r.get("errors") or []}
        except urllib.error.HTTPError as err:
            if err.code in (401, 403, 404):
                sys.exit(f"error: GitLab answered {err.code}; check GITLAB_LINT_TOKEN and GITLAB_LINT_PROJECT")
            time.sleep(int(err.headers.get("Retry-After", "60")) if err.code == 429 else 2**attempt)
        except (OSError, http.client.HTTPException, ValueError):
            time.sleep(2**attempt)
    return None


def scan(glsec, path, cwd):
    p = subprocess.run(
        [glsec, "--no-cache", "--no-repo-config", "--format", "json", str(path)],
        cwd=cwd, capture_output=True, text=True, timeout=120,
    )
    err = next((line for line in p.stderr.splitlines() if line.strip()), "")
    return p.returncode, err


def has_include(content):
    return any(line.startswith("include:") for line in content.splitlines())


def group(gitlab_valid, code, include):
    if gitlab_valid is None:
        return "not linted"
    if gitlab_valid:
        return "both accept" if code in (0, 1) else "GitLab accepts, glsec exits 2"
    if include:
        return "GitLab rejects (includes)"
    return "glsec scans, GitLab rejects" if code in (0, 1) else "both reject"


def main(argv):
    if len(argv) < 4:
        sys.exit(__doc__)
    if not os.environ.get("GITLAB_LINT_TOKEN") or not os.environ.get("GITLAB_LINT_PROJECT"):
        sys.exit("error: GITLAB_LINT_TOKEN and GITLAB_LINT_PROJECT must be set")
    glsec = str(pathlib.Path(argv[1]).resolve())
    out = pathlib.Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    cache_file = out / "lint.jsonl"
    cache = {}
    if cache_file.exists():
        for line in cache_file.open():
            r = json.loads(line)
            cache[r["sha256"]] = r
    counts = {}
    limiter = Limiter(INTERVAL)
    lock = threading.Lock()
    # An empty working directory, so no .glsec.yml or .glsec-ignore is picked up.
    with tempfile.TemporaryDirectory() as cwd, (out / "results.jsonl").open("w") as results:

        def check(name):
            path = pathlib.Path(name).resolve()
            content = path.read_text(encoding="utf-8", errors="replace")
            key = hashlib.sha256(content.encode()).hexdigest()
            with lock:
                answer = cache.get(key)
            if answer is None:
                result = lint(content, limiter)
                if result is not None:
                    answer = {"sha256": key, **result}
                    with lock:
                        cache[key] = answer
                        with cache_file.open("a") as f:
                            f.write(json.dumps(answer) + "\n")
            code, err = scan(glsec, path, cwd)
            g = group(answer and answer["valid"], code, has_include(content))
            with lock:
                counts[g] = counts.get(g, 0) + 1
                results.write(json.dumps({
                    "file": name, "sha256": key, "group": g, "glsec_exit": code, "glsec_error": err,
                    "gitlab_errors": answer["errors"] if answer else None,
                }) + "\n")
                results.flush()

        with ThreadPoolExecutor(WORKERS) as pool:
            list(pool.map(check, argv[3:]))
    for g, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"{n:6d}  {g}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
