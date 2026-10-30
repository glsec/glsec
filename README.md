<p align="center">
  <img src="assets/glsec-bg.png" alt="glsec" width="400">
</p>

# glsec

[![GitLab CI/CD Catalog](https://img.shields.io/gitlab/v/release/glsec-io%2Fglsec?logo=gitlab&label=CI%2FCD%20Catalog)](https://gitlab.com/explore/catalog/glsec-io/glsec)
[![Go Reference](https://pkg.go.dev/badge/github.com/glsec/glsec.svg)](https://pkg.go.dev/github.com/glsec/glsec)
[![codecov](https://codecov.io/gh/glsec/glsec/graph/badge.svg)](https://app.codecov.io/gh/glsec/glsec)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/glsec/glsec/badge)](https://scorecard.dev/viewer/?uri=github.com/glsec/glsec)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15508/badge)](https://www.bestpractices.dev/projects/15508)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/15508/baseline)](https://www.bestpractices.dev/projects/15508)
[![SLSA Build Level 3](https://slsa.dev/images/gh-badge-level3.svg)](#verifying-a-release)
[![agent security: cfgaudit](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/cfgaudit/cfgaudit/main/assets/badge/v1.json)](https://github.com/cfgaudit/cfgaudit)

**glsec** is a security linter for `.gitlab-ci.yml` files. It detects misconfigurations that can lead to supply-chain attacks, secret leakage, and token exfiltration — the same class of issues that [zizmor](https://github.com/zizmorcore/zizmor) and [actionlint](https://github.com/rhysd/actionlint) catch in GitHub Actions, but for GitLab CI.

**Website and rule reference: [glsec.github.io](https://glsec.github.io)**

```
$ glsec .gitlab-ci.yml

error[GL001]: image "node:latest" uses mutable tag "latest" — pin to a specific version or digest
  --> .gitlab-ci.yml:7:10 (job: build)
  |
7 |   image: node:latest
  |          ^

warn[GL002]: unquoted user-controlled variable $CI_COMMIT_REF_NAME in script — value is set by commit authors and may contain shell metacharacters
  --> .gitlab-ci.yml:14:7 (job: build)
   |
14 |     - echo $CI_COMMIT_REF_NAME
   |       ^
```

Use `--format table` for a compact one-line-per-finding view when there are many findings.

## Quick start

Add glsec to a GitLab pipeline with the [CI/CD Catalog component](https://gitlab.com/explore/catalog/glsec-io/glsec):

```yaml
include:
  - component: gitlab.com/glsec-io/glsec/glsec@v1.0.26
```

It adds a `glsec` job that runs in the `test` stage (set the `stage` input to change that) and fails on error findings. For findings in merge requests, Docker, binary or GitHub Actions setups, see [CI integration](#ci-integration). To run it locally, see [Install](#install).

## Why glsec?

| Tool | Scope |
|------|-------|
| [zizmor](https://github.com/zizmorcore/zizmor) | GitHub Actions security |
| [actionlint](https://github.com/rhysd/actionlint) | GitHub Actions syntax + some security |
| [gitlab-ci-lint](https://docs.gitlab.com/api/lint/) | GitLab CI syntax only (requires API access) |
| **glsec** | GitLab CI security — works offline, no API key needed |

- **89 rules** across the [OWASP Top 10 CI/CD Security Risks](#rules), each mapped to CWE: mutable images, secrets in variables, script injection, token exfiltration, unrestricted OIDC tokens, untrusted includes and more.
- **Findings where you review code**: GitLab Code Quality reports in merge requests, JUnit, SARIF for GitHub Code Scanning, JSON.
- **Adoptable on existing pipelines**: a baseline file and `--new-only` report only what a change introduces; suppressions carry a reason and an expiry date.
- **Trustworthy releases**: signed, with SLSA provenance and reproducible builds ([details](#verifying-a-release)).

## Install

**Package managers:**

```sh
brew install glsec/tap/glsec        # Homebrew (macOS and Linux)
aqua g -i glsec/glsec && aqua i     # aqua
mise use github:glsec/glsec         # mise
pipx install glsec                  # PyPI (or: uv tool install glsec, uvx glsec)
```

The [Homebrew tap](https://github.com/glsec/homebrew-tap) takes each release only after its archives pass the provenance check described under [Verifying a release](#verifying-a-release). glsec is in the [aqua](https://aquaproj.github.io/) standard registry from v4.578.0 on; aqua checks each download against `checksums.txt` and the provenance of glsec's release workflow. [mise](https://mise.jdx.dev/) installs the release archive from GitHub. The [PyPI package](https://pypi.org/project/glsec/) is a wheel per platform that carries the release binary, taken from the archive after the same checksum and provenance check; it has no Python code and downloads nothing at install time.

**Go install (requires Go 1.26+):**

```sh
go install github.com/glsec/glsec/cmd/glsec@latest
```

**Binary download:**

Pre-built binaries for Linux, macOS, and Windows (amd64 + arm64) are available on the [Releases page](https://github.com/glsec/glsec/releases).

```sh
# Example: Linux amd64. Archives are named glsec_<version>_<os>_<arch>.tar.gz (.zip on Windows).
curl -sSLO https://github.com/glsec/glsec/releases/download/v1.24.1/glsec_1.24.1_linux_amd64.tar.gz
tar xzf glsec_1.24.1_linux_amd64.tar.gz
./glsec --version
```

**Docker:**

```sh
docker run --rm -v "$PWD:/src:ro" -w /src ghcr.io/glsec/glsec:1.24.1
```

Without a file argument glsec scans `.gitlab-ci.yml` in the mounted directory.

To check the download before running it, see [Verifying a release](#verifying-a-release).

## Usage

Flags may appear before or after file names: `glsec .gitlab-ci.yml --format json` works like `glsec --format json .gitlab-ci.yml`. The same parsing applies to `explain`, `list` and `inventory`. Use `--` to end flag parsing; for example, `glsec -- --format` scans a file literally named `--format`.

```sh
# scan a file (exits 1 on error findings, 0 if clean, 2 on parse error)
glsec .gitlab-ci.yml

# scan multiple files or a glob in one run
glsec .gitlab-ci.yml pipelines/deploy.yml
glsec pipelines/*.yml

# scan a directory: its .gitlab-ci.yml (an error names the directory when it has none)
glsec sub

# recursively scan a tree for all .gitlab-ci.yml files
glsec --recursive .

# also pick up CI configs with non-default names/paths during a recursive scan
glsec --recursive --name '*.gitlab-ci.yml' --name 'ci/pipeline.yml' .

# CI/CD Catalog component templates are detected automatically: a `spec:` header
# followed by the template body. glsec lints the body, checks the declared inputs,
# and skips whole-pipeline rules that a template fragment cannot satisfy. A root
# .gitlab-ci.yml with a `spec:` header (pipeline inputs) is still a full pipeline.
glsec templates/my-component.yml

# jobs written with `run:` (CI/CD Steps) are scanned too — every script rule and
# the ShellCheck integration read each step's `script:` the same way they read
# `script:`, `before_script:`, and `after_script:`.
glsec .gitlab-ci.yml

# aligned table view, easier to scan when there are many findings
glsec --format table .gitlab-ci.yml

# JSON output for machine consumption
glsec --format json .gitlab-ci.yml

# SARIF output for GitHub Code Scanning
glsec --format sarif .gitlab-ci.yml > gl.sarif

# JSON carries the OWASP CICD-SEC and ASVS V14 mappings per finding, SARIF also CWE.
# Each SARIF rule has a title, help with a safe alternative, CWE tags and a
# security severity, and links to its page on glsec.github.io; example workflow:
# https://github.com/glsec/example-github-code-scanning

# Code Climate output for GitLab Code Quality (merge request report on all tiers,
# inline in the diff with Ultimate)
glsec --format codeclimate .gitlab-ci.yml > gl-code-quality.json

# JUnit output for the pipeline Tests tab / MR test widget (works on all tiers)
glsec --format junit .gitlab-ci.yml > glsec-junit.xml

# GitLab SAST report for the vulnerability report and MR security widget (Ultimate)
glsec --format gitlab-sast .gitlab-ci.yml > gl-sast-report.json

# treat warn findings as hard failures (exit 1)
glsec --strict .gitlab-ci.yml

# advisory mode: always exit 0, even with findings
glsec --no-exit-codes .gitlab-ci.yml

# skip rules for keywords your GitLab version doesn't have yet
glsec --gitlab-version 16.0 .gitlab-ci.yml

# no ANSI colours (also when NO_COLOR is set)
glsec --no-color .gitlab-ci.yml

# exclude a file or directory from scanning
glsec --exclude vendor/ .gitlab-ci.yml

# run only specific rules (comma-separated or repeated); an unknown rule ID is an error
glsec --only GL001,GL003 .gitlab-ci.yml

# skip specific rules; an unknown rule ID only warns
glsec --skip GL008,GL022 .gitlab-ci.yml

# CycloneDX BOM of the images and includes the pipeline pulls in (see Pipeline inventory)
glsec inventory .gitlab-ci.yml > pipeline.cdx.json

# list all rules (ID, severity, OWASP, description); --format json / --owasp also supported
glsec list
glsec list --owasp CICD-SEC-4

# explain a specific rule
glsec explain GL001

# baseline existing findings so only new violations are reported
glsec --generate-ignore .gitlab-ci.yml
glsec .gitlab-ci.yml  # now exits 0; new violations will be caught

# audit mode: report everything, bypassing all glsec suppressions
glsec --no-ignores .gitlab-ci.yml  # ignores inline # glsec:ignore and the .glsec-ignore baseline

# scan a repository you don't trust: its .glsec.yml and suppressions don't apply
glsec --no-repo-config --no-ignores .gitlab-ci.yml

# gate MRs on "don't make it worse": fail only on findings not in the baseline
glsec --new-only .gitlab-ci.yml                       # diff against .glsec-ignore
glsec --new-only --baseline main.json .gitlab-ci.yml  # diff against a saved JSON snapshot
```

JSON, SARIF, Code Quality, JUnit and GitLab SAST reports write absolute file paths inside the working directory as relative paths, using `/` separators. Paths outside that directory retain their supplied spelling. SARIF marks locations inside the working directory with `uriBaseId: "%SRCROOT%"` so code scanning can resolve them against the source root. This avoids publishing runner directory names for files inside the checkout.

`--generate-ignore` rewrites only the entries the run could have reported: those for a file it scanned and a rule that ran. Entries for other pipeline files, and for rules left out with `--only`, `--skip` or `.glsec.yml`, stay as they are, and so do comments and an entry's `exp:` date when the finding is still there. `glsec --generate-ignore --only GL001 .gitlab-ci.yml` refreshes the GL001 entries and keeps the rest.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No `error`-severity findings (warn-only findings exit 0 by default) |
| 1 | One or more `error` findings; or any finding when `--strict` is set |
| 2 | Usage error (including an unknown rule ID in `--only`, or `--only` and `--skip` that leave no rule), file could not be parsed, a suppression policy violation, or with `--strict`, every file excluded |

On exit 2 after the scan started, the machine-readable reports still list the findings of the files that were scanned and say which file failed and why, so a failed scan doesn't read as a clean one: an `errors` array in `json`, a `blocker` issue with check name `glsec-error` in `codeclimate`, an unsuccessful invocation with the error as a notification in `sarif`, a test case with an `<error>` in `junit`, and `scan.status: failure` with a `fatal` message in `gitlab-sast`. A usage or config error stops glsec before it writes a report.

glsec reads only regular files of up to 64 MB as pipelines: a FIFO, a device, a directory or a larger file is an exit 2 for the file named on the command line, and a child pipeline file like that is skipped with a warning.

Use `--strict` to treat `warn` findings as hard failures (exit 1). Use `--no-exit-codes` to always exit 0 regardless of findings (advisory/informational mode). All flags can also be set in `.glsec.yml`:

```yaml
strict: true        # warn findings cause exit 1
no-exit-codes: true # never exit 1 (overrides strict)

# Optional container-image policies (GL065 and GL001):
allowed_registries: []       # empty permits any registry
require_image_digest: false  # true also warns on version tags without a digest

exclude_paths:
  - legacy/.gitlab-ci.yml
  - infra/old-pipelines/**
  - vendor/

recursive_patterns:    # extra CI-config names/paths for --recursive (default: .gitlab-ci.yml)
  - '*.gitlab-ci.yml'   # no "/" → matched against the basename
  - ci/pipeline.yml     # contains "/" → matched against the path relative to each scanned dir
```

If the exclusions cover every file glsec was asked to scan, it says so on stderr instead of finishing silently; with `--strict` that is an error (exit 2).

### Baseline diff (`--new-only`)

For adopting glsec on an established pipeline without drowning in pre-existing findings, `--new-only` reports — and fails — only on findings **not** in a baseline, leaving the existing backlog out of the way. It honours `--strict` and `min-severity`, so the exit code reflects new findings alone.

Two baseline sources are supported:

- **`.glsec-ignore`** (default, no flag needed) — the file written by `--generate-ignore`. Matched on `(rule, file)`, since that format carries no message.
- **`--baseline <file.json>`** — a snapshot saved from a prior `--format json` run (e.g. a scan of the target branch). Matched on `(rule, file, message)`.

Matching is **line-insensitive**: a finding that merely shifts to a different line because unrelated content moved is recognised as the same finding and stays in the baseline, rather than resurfacing as "new". Duplicates are tracked by count, so a genuinely new third occurrence of an already-baselined finding is still reported. The JSON snapshot matches more precisely (it has the message); the `.glsec-ignore` baseline is the simple, zero-setup case. In `--new-only` mode the `.glsec-ignore` line suppression is replaced by this diff; inline `# glsec:ignore` directives still apply.

Snapshot the base branch at the **same path** (the `file` field is part of the match), then fail only on what the MR adds:

```bash
git checkout origin/main -- .gitlab-ci.yml
glsec --format json .gitlab-ci.yml > base.json
git checkout HEAD -- .gitlab-ci.yml
glsec --new-only --baseline base.json .gitlab-ci.yml
```

### Suppressions

Silence a finding on a single line with an inline comment, optionally with a reason after `--`:

```yaml
build:
  image: node:latest  # glsec:ignore GL001 -- base image is pinned by the platform
```

A suppression can also carry an **expiry date**, so accepted risk gets re-reviewed instead of becoming permanent:

```yaml
deploy:
  script:
    - ./deploy.sh  # glsec:ignore GL013 exp:2026-12-01 -- accepted until the migration lands
```

Once the date has passed the suppression stops applying, the finding is reported again, and glsec notes on stderr that the suppression expired, so a finding that reappears is traceable to the date rather than looking like a new violation. The expiry date itself is inclusive. A malformed date counts as expired, so a typo surfaces the finding rather than hiding it forever.

The same token works in the `.glsec-ignore` baseline, appended to a line:

```
.gitlab-ci.yml:14 GL013 exp:2026-12-01
```

Entries without the token never expire, so existing ignore files keep working unchanged.

To stop undocumented suppressions creeping in, require a reason:

```sh
glsec --require-ignore-reason .gitlab-ci.yml
```

```yaml
# .glsec.yml
require_ignore_reason: true
```

Any inline `# glsec:ignore` without a `-- reason` is then reported with its file and line, and glsec exits 2. Off by default, so existing suppressions keep working. The `.glsec-ignore` baseline is exempt because its format has no reason column. Note that enabling this disables the result cache: the check runs while findings are collected, so a cache hit would skip it.

### Scanning repositories you don't trust

`.glsec.yml`, `.glsec-ignore` and inline `# glsec:ignore` comments normally live in the repository being scanned. That is what you want when a project checks itself, but not when the check is meant to hold a repository to a standard it can't change: a pipeline execution or compliance policy, a central job that scans other projects, or a reviewer checking out a fork. There the repository could turn rules off, exclude files or suppress findings.

```sh
glsec --no-repo-config --no-ignores .gitlab-ci.yml
glsec --no-repo-config --no-ignores --config /policies/glsec.yml .gitlab-ci.yml  # your own settings
```

`--no-repo-config` ignores a `.glsec.yml` in the working directory (glsec says so on stderr); a file passed with `--config` is still read. `--no-ignores` drops all suppressions. Neither is needed when a project scans its own merge requests in its own pipeline, since the author can change the pipeline itself there.

With the GitLab component, set the inputs `no_repo_config: true` and `no_ignores: true` (component v1.0.25 or later). To make glsec mandatory for a group on GitLab Ultimate, run the component from a pipeline execution policy; the [component README](https://gitlab.com/glsec-io/glsec#enforcing-glsec-with-a-pipeline-execution-policy) has a tested example, including the `rules:` the job needs there to run in merge request pipelines.

### Result cache

glsec caches results in `$XDG_CACHE_HOME/glsec` (`~/.cache/glsec` by default), keyed on the glsec version, the date, the scanned files, the config and the suppressions, so an unchanged pipeline is not scanned twice on the same day. Entries from earlier days can't be hit again and are removed when glsec stores a new one. `--no-cache` skips it for one run; `--clear-cache` empties it.

In CI (`CI=true`) glsec doesn't use the cache: a job starts in a fresh container, so the cache would only help if the project kept it between pipelines with `cache:`, which takes longer than the scan and shares a file that decides what glsec reports. `--cache` turns it on for such a run anyway; `--no-cache` wins over it.

A cached result decides what glsec reports, so glsec only uses a cache directory that belongs to the current user and that nobody else can write to, reads only regular files from it, and never uses a cache that lies inside the directory of the pipeline being scanned (as with `XDG_CACHE_HOME=$CI_PROJECT_DIR/.cache`), where the repository could ship entries of its own.

## Rules

89 rules across 8 [OWASP CI/CD security categories](https://owasp.org/www-project-top-10-ci-cd-security-risks/):

| Category | OWASP | Rules |
|----------|-------|-------|
| Credential Hygiene | CICD-SEC-6 | GL004, GL005, GL006, GL010, GL014, GL018, GL021, GL027, GL029, GL032, GL033, GL035, GL036, GL037, GL038, GL040, GL052, GL059, GL062, GL066, GL068, GL070, GL073, GL088 |
| Dependency & Image Pinning | CICD-SEC-3 | GL001, GL003, GL011, GL016, GL022, GL023, GL026, GL046, GL064, GL069, GL072, GL075, GL079 |
| Component & Third-Party Integrity | CICD-SEC-4, CICD-SEC-8 | GL002, GL007, GL015, GL025, GL041, GL044, GL051, GL053, GL065, GL067, GL078, GL083, GL084, GL085 |
| Supply Chain Integrity | CICD-SEC-9 | GL020, GL045 |
| Pipeline Flow & Access Control | CICD-SEC-1, CICD-SEC-5 | GL008, GL009, GL012, GL013, GL017, GL019, GL034, GL039, GL043, GL055, GL071, GL074, GL080, GL081, GL082, GL089 |
| Insecure Configuration | CICD-SEC-7 | GL024, GL028, GL030, GL031, GL042, GL047, GL048, GL049, GL050, GL054, GL056, GL057, GL058, GL060, GL061, GL063, GL076, GL077, GL086, GL087 |

→ **[Full rule reference with descriptions and examples](https://glsec.github.io/rules/)** on glsec.github.io, built from [docs/rules.md](docs/rules.md) at each release

**Not covered:** [CICD-SEC-2](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management) (Identity & Access Management) and [CICD-SEC-10](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-And-Visibility) (Insufficient Logging & Visibility) are not detectable from static `.gitlab-ci.yml` analysis — they require platform-level context such as GitLab group/project settings, audit logs, or API access.

### Secrets in reports

glsec masks the secret values it recognises before it writes a report, in every format, in finding messages and in the source lines of the text output: the token formats GL006 knows, the password in `scheme://user:password@host`, `Authorization: Bearer|Basic|Token …`, `PRIVATE-TOKEN:` / `JOB-TOKEN:` headers, `curl -u user:password`, `--password …`, and the value of a variable whose name ends in `_TOKEN`, `_SECRET`, `_PASSWORD`, `_KEY` and the like. A masked value keeps its length and a short prefix (`ghp_************`), so the caret under the source line still points at the right column. Variable references such as `$TOKEN` stay as they are.

The value is in the repository anyway, but a report travels further: into job logs, which are often public, Code Quality and JUnit artifacts, code scanning, and pasted bug reports. GitLab's log masking doesn't catch it, since it isn't a CI/CD variable. `--no-redact` shows the values for local debugging. It is a command-line flag only: `.glsec.yml` comes from the repository being scanned, so it can't turn masking off.

### Shell assumptions

The script-analysis rules (e.g. GL002, GL024, GL025, GL047, GL048, GL050) assume **POSIX shell** (`bash`/`sh`) semantics — the default for Linux and macOS runners. PowerShell pipelines on Windows runners use different syntax (`$env:VAR` instead of `$VAR`, `Invoke-WebRequest` instead of `curl`, etc.), so these rules will not match them. GL011 also recognises PowerShell download-and-execute (`iwr URL | iex`, `iex (irm URL)`), and GL021 recognises secret variables printed by PowerShell commands such as `Write-Host` and `Write-Output`. **A Windows-runner job that emits no findings has not been meaningfully checked for shell issues** — don't treat the absence of findings there as a clean bill of health. GL024 skips jobs whose runner tags contain `windows`, because PowerShell has no `pipefail`.

### Variables in `rules:`

Rules that check variable values read every `variables:` block GitLab can apply: top-level, `default:`, per job, and the `variables:` of each `workflow:rules` and job `rules:` entry. A value moved into a rule is committed in the file all the same, so it is reported where it is set. glsec doesn't evaluate the `if:` conditions; [GL082](docs/rules/GL082.md) alone skips rules that only match scheduled pipelines.

### Reusable configuration

glsec resolves YAML anchors, aliases and merge keys (`&anchor` / `*alias` / `<<: *anchor`) and GitLab [`!reference` tags](https://docs.gitlab.com/ci/yaml/yaml_optimization/#reference-tags) that point within the same file. Content pulled in either way is analysed as if it were inlined into the job that uses it, so issues hidden in shared `.template` blocks are caught. A finding in an anchor that several jobs share is reported once, at the anchor. References that resolve into `include:`d files are not yet expanded.

Local child pipelines are scanned along with their parent: every `trigger: include:` entry that names a local file (a path, `local:`, as a list or a single entry) is followed, recursively, with paths taken from the repository root as GitLab does. The root is the directory of the pipeline file you scan. Remote, `artifact:`, `project:`, `template:` and `component:` includes are not fetched, and a missing child only produces a warning. A path that leads outside the root, through `..` or a symbolic link, is skipped with a warning; GitLab rejects such includes too.

## ShellCheck integration

glsec can optionally pass `script:`, `before_script:`, and `after_script:` blocks to [ShellCheck](https://www.shellcheck.net/) for deeper shell analysis. This is **opt-in** and requires ShellCheck to be installed separately.

Enable it in `.glsec.yml`:

```yaml
shellcheck:
  enabled: true
```

glsec runs `shellcheck` from `PATH`. To use another binary, pass `--shellcheck-path /opt/bin/shellcheck`. A `path:` under `shellcheck:` is honoured only in a config file given with `--config`; in a `.glsec.yml` that glsec picks up from the working directory it is ignored with a warning, because that file usually comes from the repository being scanned, and a merge request could otherwise point it at a program of its own.

ShellCheck findings are reported alongside GL findings and use `SC` rule IDs:

```
WARN   .gitlab-ci.yml:12  SC2086  [build]  Double quote to prevent globbing and word splitting.
```

If the ShellCheck binary is not found, glsec prints a warning to stderr and continues scanning normally. A ShellCheck that is there but fails (an exit code above 1, or output that isn't its JSON) or takes longer than 30 seconds for one job stops the scan with exit 2, with the job and ShellCheck's error message: ShellCheck was turned on, so a run without its findings must not pass as clean.

**Suppressing specific codes** — inline:

```yaml
  script:
    - echo $CI_COMMIT_REF_NAME  # glsec:ignore SC2086 -- set by platform
```

Or globally in `.glsec.yml`:

```yaml
rules:
  SC2086: off
```

ShellCheck's own inline directives (`# shellcheck disable=SC2086`) are also respected. `--no-ignores` bypasses glsec's suppressions (inline `# glsec:ignore` and the `.glsec-ignore` baseline) but **not** ShellCheck's native `# shellcheck disable=` directives, which are handled inside ShellCheck itself.

---

## Pre-commit hook

glsec ships a [pre-commit](https://pre-commit.com/) hook so `.gitlab-ci.yml` issues are caught before they're pushed. Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/glsec/glsec
    rev: v1.24.1
    hooks:
      - id: glsec
```

Then `pre-commit install` once; the hook runs on every commit that touches a matching file. Run it across the whole tree at any time with `pre-commit run glsec --all-files`.

Three hook variants are provided — pick the one that fits how you install glsec:

| Hook id | `language` | Use when |
|---------|------------|----------|
| `glsec` | `golang` | Default — pre-commit builds glsec from source at the pinned `rev` (needs a Go toolchain; no separate install). |
| `glsec-system` | `system` | You already have a `glsec` binary on `PATH` (fastest; version is whatever is installed). |
| `glsec-docker` | `docker_image` | You'd rather not install anything but Docker — runs `ghcr.io/glsec/glsec` (pin the image version in your own config if reproducibility matters). |

By default the hook only matches files named `.gitlab-ci.yml`. To also scan custom CI-config names/paths (see `--recursive --name`), override `files:`:

```yaml
      - id: glsec
        files: '(^|/)[^/]*\.gitlab-ci\.yml$'   # also matches *.gitlab-ci.yml
```

The hook exits non-zero (failing the commit) on `error` findings or parse errors, matching glsec's normal [exit codes](#exit-codes).

---

## Claude Code plugin

glsec ships as a [Claude Code](https://claude.com/claude-code) plugin so Claude can scan your GitLab CI config on demand and as you edit it. Install it from glsec's own marketplace:

```
/plugin marketplace add glsec/glsec
/plugin install glsec@glsec
```

The marketplace installs the plugin from the commit of the latest release tag, not from `main`, so changes merged after a release reach you only with the next one.

This adds:

- **`/glsec:scan`** — a command that runs glsec over the project and has Claude explain and remediate each finding.
- **An edit hook** — after Claude writes or edits a `.gitlab-ci.yml` (or a `.gitlab/*.yml`) file, glsec scans it automatically and surfaces any findings.

No Go toolchain is required: the plugin bundles a small POSIX wrapper that resolves a `glsec` binary in order of preference:

1. an existing one on your `PATH`, if it is at least the version the plugin pins. Empty and relative `PATH` entries are skipped, since the hook runs inside whatever project is open;
2. a cached download;
3. the prebuilt release asset, downloaded, **verified against `checksums.txt`** and, if [cosign](https://github.com/sigstore/cosign) or an authenticated [GitHub CLI](https://cli.github.com/) with `gh attestation` is installed, **against its signed build provenance** (see [Verifying a release](#verifying-a-release)), then cached. Without either tool it says on stderr that only the checksum was checked.

Supported on **Linux and macOS** (amd64/arm64); the wrapper needs `curl` or `wget`, and the edit hook needs `jq`. On other platforms it prints an install hint instead.

---

## CI integration

> **Runnable examples for every pattern below:** [gitlab.com/glsec-io/examples](https://gitlab.com/glsec-io/examples) — [Catalog component](https://gitlab.com/glsec-io/examples/component) · [Catalog + Code Quality](https://gitlab.com/glsec-io/examples/component-code-quality) · [Docker image](https://gitlab.com/glsec-io/examples/docker) · [Binary download](https://gitlab.com/glsec-io/examples/binary)

### GitLab CI Catalog component (recommended)

Use the official component from the [GitLab CI Catalog](https://gitlab.com/explore/catalog/glsec-io/glsec) — no need to manage image pins or script wiring yourself:

```yaml
include:
  - component: gitlab.com/glsec-io/glsec/glsec@v1.0.26

stages:
  - test
```

To see findings in merge requests, add the `glsec-code-quality` template. The merge request's Code Quality report works on **all GitLab tiers**; with Ultimate the findings also appear inline in the diff:

```yaml
include:
  - component: gitlab.com/glsec-io/glsec/glsec-code-quality@v1.0.26

stages:
  - test
```

Pin to an explicit component tag (not `@~latest`) — glsec's own GL003 / GL041 rules flag floating refs.

**Coloured output in CI logs:** glsec auto-disables ANSI colors when stdout is not a terminal (the standard convention). Force colors back on by setting `FORCE_COLOR=1` (or `CLICOLOR_FORCE=1`) in your pipeline variables:

```yaml
variables:
  FORCE_COLOR: "1"
```

**Component repo and full input reference:** https://gitlab.com/glsec-io/glsec

**Runnable example projects:** https://gitlab.com/glsec-io/examples

### GitLab CI — Docker image

If you need more control than the Catalog component offers, use the pre-built image from GHCR directly:

```yaml
glsec:
  stage: test
  image:
    name: ghcr.io/glsec/glsec:1.24.1
    entrypoint: [""]
  script:
    - glsec .gitlab-ci.yml
```

The `entrypoint: [""]` override is required: the image sets `ENTRYPOINT ["glsec"]` for `docker run` convenience, which conflicts with GitLab Runner's shell wrapper. Pin to a specific tag (`1.24.1`, not `:latest`) for reproducible pipelines.

### GitLab CI — binary download

For pipelines that cannot pull from GHCR:

```yaml
variables:
  GLSEC_VERSION: "1.24.1"

glsec:
  stage: test
  image: alpine:3.20
  before_script:
    - apk add --no-cache curl tar
    - curl -sSLO "https://github.com/glsec/glsec/releases/download/v${GLSEC_VERSION}/glsec_${GLSEC_VERSION}_linux_amd64.tar.gz"
    - curl -sSL "https://github.com/glsec/glsec/releases/download/v${GLSEC_VERSION}/checksums.txt" | grep "glsec_${GLSEC_VERSION}_linux_amd64.tar.gz" | sha256sum -c
    - tar xzf "glsec_${GLSEC_VERSION}_linux_amd64.tar.gz"
  script:
    - ./glsec .gitlab-ci.yml
```

### GitLab Code Quality integration

Show findings in the merge request's **Code Quality report**, on all GitLab tiers. With Ultimate they also appear inline in the diff, and Premium adds a Code Quality tab to the pipeline ([GitLab's tier overview](https://docs.gitlab.com/ci/testing/code_quality/)). The easiest path is the `glsec-code-quality` template from the [Catalog component](#gitlab-ci-catalog-component-recommended) above. The equivalent manual setup:

```yaml
glsec:
  stage: test
  image:
    name: ghcr.io/glsec/glsec:1.24.1
    entrypoint: [""]
  script:
    # exit 1 means findings, which the report shows; let exit 2 fail the job
    - glsec --format codeclimate .gitlab-ci.yml > gl-code-quality.json || [ $? -eq 1 ]
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality.json
```

Severity mapping (glsec → Code Climate): `error` → `critical`, `warn` → `major`, `info` → `info`.

### GitLab vulnerability report and security widget (Ultimate)

On GitLab Ultimate, `--format gitlab-sast` (glsec 1.25.0 and later) writes a SAST report in GitLab's security report schema (version 15.2.1). Uploaded as `artifacts:reports:sast`, the findings appear in the project's **vulnerability report**, where they can be triaged, and in the merge request's **security widget**, which lists the findings the merge request adds:

```yaml
glsec-sast:
  stage: test
  image:
    name: ghcr.io/glsec/glsec:1.24.1
    entrypoint: [""]
  script:
    - glsec --format gitlab-sast --no-exit-codes .gitlab-ci.yml > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

Each finding becomes one vulnerability:

| Report field | From glsec |
|---|---|
| name | rule ID and title, e.g. `GL001: Mutable image tag` |
| severity | `error` → High, `warn` → Medium, `info` → Low |
| identifiers | the rule ID with a link to its page (primary), the CWE, the OWASP CICD-SEC category |
| location | file and line |
| description, solution | the finding's message and job, and the link to the rule page |

Things to know:

- On Free and Premium, GitLab accepts the report but doesn't show it. Use [Code Quality](#gitlab-code-quality-integration) there; on Ultimate both can run side by side.
- GitLab matches a finding from one pipeline to the next by its file and line. A merge request that adds or removes lines above an unchanged finding shows it in the widget as fixed and as new.
- `--no-exit-codes` keeps the job green, so the report is uploaded. To fail the pipeline on findings as well, run glsec a second time without it, or use a [pipeline execution policy](https://gitlab.com/glsec-io/glsec#enforcing-glsec-with-a-pipeline-execution-policy).

### Pipeline inventory (CycloneDX)

`glsec inventory` lists what a pipeline pulls in as a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) bill of materials, so SBOM tools such as Dependency-Track can track it next to your application's dependencies. It reports no findings and exits 0, or 2 when the file can't be read. With `--format jobs` it lists the jobs glsec scans instead, as JSON with name and line: the visible jobs of the pipeline, without hidden templates.

```sh
glsec inventory .gitlab-ci.yml > pipeline.cdx.json
```

| Listed | CycloneDX type | Name and version |
|---|---|---|
| `image:` of every job, through `extends:`, anchors, `default:` and a top-level `image:` | `container` | image and tag or digest, with a `pkg:docker` purl |
| `services:` | `container` | the same |
| `include: component:` | `library` | component path and version |
| `include: project:` | `library` | project and `ref:`, the files as `glsec:file` properties |
| `include: remote:` (and a URL written as a plain string) | `library` | the URL, also as a `distribution` reference |
| `include: template:` | `library` | template name |

Includes of `trigger:` jobs count too. Every component carries these properties:

- `glsec:kind`: `image`, `service`, `component`, `project`, `remote` or `template`
- `glsec:pinning`:
  - `digest`: an image digest, or `integrity:` on a remote include
  - `sha`: a full commit SHA
  - `version`: an exact version, or a tag that isn't a known moving one
  - `mutable`: for example `latest`, `17`, `main`, `~latest` or `@1.2`
  - `none`: no tag or ref
  - `unresolved`: the reference contains a CI variable or input
  - `gitlab`: a template, which moves with your GitLab version
- `glsec:job`: each job that uses an image or service
- `glsec:line`: where the reference first appears

The pipeline file is the BOM's `metadata.component`; a single `dependencies` entry links it to every component. Jobs are not components of their own, since they are not software a BOM tool could track; the image properties name them instead.

The output depends only on the pipeline: there is no timestamp, and the serial number is derived from the content, so an unchanged pipeline gives a byte-identical BOM and diffs stay clean. Upload it to Dependency-Track as a project BOM (`PUT /api/v1/bom`) or with any CycloneDX-aware tool.

Like the rest of glsec it works offline: includes are listed, not fetched, so what an include or component brings in itself is not part of the BOM. `local:` and `artifact:` includes are left out, since they come from the repository or the pipeline. There is no vulnerability data; an SBOM tool adds that from the purls.

### GitHub Actions

```yaml
- name: Run glsec
  env:
    GLSEC_VERSION: "1.24.1"
  run: |
    curl -sSLO "https://github.com/glsec/glsec/releases/download/v${GLSEC_VERSION}/glsec_${GLSEC_VERSION}_linux_amd64.tar.gz"
    tar xzf "glsec_${GLSEC_VERSION}_linux_amd64.tar.gz"
    ./glsec .gitlab-ci.yml
```

### MegaLinter

glsec ships a [MegaLinter](https://megalinter.io) plugin. Add it to `.mega-linter.yml`:

```yaml
PLUGINS:
  - https://raw.githubusercontent.com/glsec/glsec/v1.24.1/mega-linter-plugin-glsec/glsec.megalinter-descriptor.yml
```

The linter key is `GITLAB_GLSEC`. It lints files named `.gitlab-ci.yml` or `*.gitlab-ci.yml` (`.yaml` too); widen that with `GITLAB_GLSEC_FILE_NAMES_REGEX`. Extra flags go in `GITLAB_GLSEC_ARGUMENTS`, or in a `.glsec.yml` at the repository root. With `SARIF_REPORTER: true`, findings are included in MegaLinter's SARIF report.

The plugin downloads the glsec release pinned in its [descriptor](mega-linter-plugin-glsec/glsec.megalinter-descriptor.yml) and verifies it against `checksums.txt` before installing. The descriptor decides what gets installed, so load it from a release tag as above: a tag can't change under you, and moving to a new glsec version is a one-line change you can review. Loading it from `main` instead installs whatever the descriptor on `main` says at the time of each run.

## Verifying a release

Every release is signed and carries build provenance, so you can confirm an artifact really came from this repository's workflow before trusting it. Signing is keyless through [Sigstore](https://www.sigstore.dev/), so there is no public key to fetch or rotate.

The release binaries and the container image meet [SLSA](https://slsa.dev/spec/v1.0/levels) **Build Level 3** from 1.21.0 on: they are built in reusable workflows (`build-release.yml`, `build-image.yml`) that the release workflow only calls, so the build workflow, not the workflow a tag push triggers, signs the provenance. That is the isolation GitHub documents as [SLSA v1 Build Level 3 for artifact attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3). Releases 1.11.0 to 1.20.0 meet Build Level 2: their provenance is signed by GitHub's hosted build platform, but by the release workflow itself.

**Release binaries** carry a SLSA provenance attestation. Verify a downloaded archive with the [GitHub CLI](https://cli.github.com/); `--signer-workflow` requires that the build workflow signed it (Build Level 3):

```sh
gh attestation verify glsec_1.24.1_linux_amd64.tar.gz --owner glsec \
  --signer-workflow glsec/glsec/.github/workflows/build-release.yml
```

For releases before 1.21.0, drop `--signer-workflow`.

The same attestation is attached to each release as `glsec_<version>.sigstore.json` (Sigstore bundle) and `glsec_<version>.intoto.jsonl` (its DSSE envelope), so you can also verify without the GitHub API, for example from a mirror:

```sh
cosign verify-blob-attestation \
  --bundle glsec_1.24.1.sigstore.json --new-bundle-format --type slsaprovenance1 \
  --certificate-identity-regexp '^https://github.com/glsec/glsec/\.github/workflows/(build-)?release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  glsec_1.24.1_linux_amd64.tar.gz
```

One bundle covers every archive and `checksums.txt`. Releases from 1.11.0 on carry these files; in 1.11.0 the bundle covers the archives but not `checksums.txt`, and older releases have no provenance. The identity regex accepts `release.yml`, which signed releases before 1.21.0, and `build-release.yml`, which signs them from 1.21.0 on; use only the latter to require Build Level 3.

**The container image** is signed with [cosign](https://github.com/sigstore/cosign) and carries provenance plus an SBOM attestation:

```sh
cosign verify ghcr.io/glsec/glsec:1.24.1 \
  --certificate-identity-regexp 'https://github.com/glsec/glsec/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# list everything attached to the image (signature, provenance, SBOM)
cosign tree --experimental-oci11 ghcr.io/glsec/glsec:1.24.1
```

To require Build Level 3 provenance for the image (1.21.0 and later):

```sh
gh attestation verify oci://ghcr.io/glsec/glsec:1.24.1 --owner glsec \
  --signer-workflow glsec/glsec/.github/workflows/build-image.yml
```

The two `--certificate-*` flags are what bind the signature to this repository's GitHub Actions workflow. Without them `cosign verify` accepts a signature from any identity, which defeats the point.

Use cosign v3 or newer. The image is signed in Sigstore's bundle format and the attestations are stored as OCI referrers, so cosign v2 reports `no signatures found`, and `cosign tree` without `--experimental-oci11` shows nothing.

**Checksums** are published as `checksums.txt` next to the archives:

```sh
curl -sSLO https://github.com/glsec/glsec/releases/download/v1.24.1/checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

`checksums.txt` is itself attested, so you can verify the checksums file first and then trust every digest it lists:

```sh
gh attestation verify checksums.txt --owner glsec
```

**Reproducing a release**: release builds are reproducible from 1.21.0 on. Check out the tag and build it with the Go version from `go.mod` (the `toolchain` line from 1.24.1 on, before that the `go` line) and exactly the GoReleaser version pinned in `.github/workflows/build-release.yml` (v2.18.3 for 1.21.0); another GoReleaser version packs the archives differently. The archives must match the published `checksums.txt`:

```sh
VERSION=1.24.1
git clone https://github.com/glsec/glsec && cd glsec
git checkout "v${VERSION}"
goreleaser release --clean --skip=publish,sbom
curl -sSL "https://github.com/glsec/glsec/releases/download/v${VERSION}/checksums.txt" | grep -v '\.sbom\.json$' > published.txt
(cd dist && sha256sum -c ../published.txt)
```

The SBOM files are left out because syft writes timestamps into them; they are not part of the provenance either. CI checks on every change to the build that two builds of the same commit are identical.

**SBOMs**: the container image carries its SBOM as a signed attestation, listed by `cosign tree` above. The per-archive `.sbom.json` files are published as plain release assets rather than attestations, deliberately. Each contains four entries: glsec itself, its single dependency `gopkg.in/yaml.v3`, the Go standard library, and the archive's own digest. That is the same information `go.mod` already makes public, and the archive it describes is covered by provenance, so a swapped SBOM cannot make a tampered archive verify. If you need an SBOM you can trust end to end, use the image attestation or regenerate one from a verified archive with [syft](https://github.com/anchore/syft).

## Badge

Using glsec in your pipeline? Show it in your README:

[![CI/CD security: glsec](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/glsec/glsec/main/assets/badge/v1.json)](https://github.com/glsec/glsec)

```markdown
[![CI/CD security: glsec](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/glsec/glsec/main/assets/badge/v1.json)](https://github.com/glsec/glsec)
```

To show it on a GitLab project page, add it under **Settings → General → Badges** with:

- **Link**: `https://github.com/glsec/glsec`
- **Badge image URL**: `https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/glsec/glsec/main/assets/badge/v1.json`

The badge says that a project runs glsec, not that its last pipeline passed; GitLab's own pipeline badge shows that.

## Contributing

If glsec is useful to you, a GitHub star helps others find it.

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a bug, a false positive or a missing rule, see [Reporting a bug](CONTRIBUTING.md#reporting-a-bug).

How glsec works inside, what it defends against and why its design holds up, is described in [ARCHITECTURE.md](ARCHITECTURE.md); who maintains it and who has access to what, in [GOVERNANCE.md](GOVERNANCE.md); how it is tested, in [TESTING.md](TESTING.md); where it is heading, in [ROADMAP.md](ROADMAP.md); how a release is made, in [RELEASING.md](RELEASING.md). Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Repositories

glsec is developed in this repository. The GitLab integrations live on gitlab.com:

| Repository | Contents |
|---|---|
| [github.com/glsec/glsec](https://github.com/glsec/glsec) | The scanner, its rules and documentation, releases, the container image, the pre-commit hook, the Claude Code and MegaLinter plugins |
| [gitlab.com/glsec-io/glsec](https://gitlab.com/glsec-io/glsec) | The GitLab CI/CD Catalog component (`glsec` and `glsec-code-quality` templates) |
| [gitlab.com/glsec-io/examples/component](https://gitlab.com/glsec-io/examples/component) | Example: the Catalog component |
| [gitlab.com/glsec-io/examples/component-code-quality](https://gitlab.com/glsec-io/examples/component-code-quality) | Example: the component with Code Quality annotations in merge requests |
| [gitlab.com/glsec-io/examples/docker](https://gitlab.com/glsec-io/examples/docker) | Example: the container image |
| [gitlab.com/glsec-io/examples/binary](https://gitlab.com/glsec-io/examples/binary) | Example: the release binary |

## Security

To report a vulnerability in glsec, see [SECURITY.md](SECURITY.md). It also documents the trust boundary, which is worth reading before filing: a missed or wrong finding is a normal bug, while glsec misbehaving on attacker-supplied input is not.

## License

Apache 2.0. The repository follows the [REUSE specification](https://reuse.software/): every file carries or is assigned its copyright and license, and `reuse lint` passes.
