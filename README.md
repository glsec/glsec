<p align="center">
  <img src="assets/glsec-bg.png" alt="glsec" width="400">
</p>

# glsec

**glsec** is a security linter for `.gitlab-ci.yml` files. It detects misconfigurations that can lead to supply-chain attacks, secret leakage, and token exfiltration — the same class of issues that [zizmor](https://github.com/zizmorcore/zizmor) and [actionlint](https://github.com/rhysd/actionlint) catch in GitHub Actions, but for GitLab CI.

```
$ glsec .gitlab-ci.yml

ERROR  .gitlab-ci.yml:7   GL001  image "node:latest" uses mutable tag "latest" — pin to a specific version or digest
WARN   .gitlab-ci.yml:14  GL002  variable $CI_COMMIT_REF_NAME in script is user-controlled and unquoted — wrap in double quotes
ERROR  .gitlab-ci.yml:3   GL003  project include "company/templates" missing "ref" — defaults to HEAD of default branch (mutable)
```

## Why glsec?

| Tool | Scope |
|------|-------|
| [zizmor](https://github.com/zizmorcore/zizmor) | GitHub Actions security |
| [actionlint](https://github.com/rhysd/actionlint) | GitHub Actions syntax + some security |
| [gitlab-ci-lint](https://docs.gitlab.com/api/lint/) | GitLab CI syntax only (requires API access) |
| **glsec** | GitLab CI security — works offline, no API key needed |

## Install

**Go install (requires Go 1.21+):**

```sh
go install github.com/glsec/glsec@latest
```

**Binary download:**

Pre-built binaries for Linux, macOS, and Windows (amd64 + arm64) are available on the [Releases page](https://github.com/glsec/glsec/releases).

```sh
# Example: Linux amd64
curl -sSL https://github.com/glsec/glsec/releases/latest/download/glsec_linux_amd64.tar.gz | tar xz
./glsec --version
```

Homebrew coming soon.

## Usage

```sh
# scan a file (exits 1 on error findings, 0 if clean, 2 on parse error)
glsec .gitlab-ci.yml

# scan multiple files or a glob in one run
glsec .gitlab-ci.yml pipelines/deploy.yml
glsec pipelines/*.yml

# recursively scan a tree for all .gitlab-ci.yml files
glsec --recursive .

# also pick up CI configs with non-default names/paths during a recursive scan
glsec --recursive --name '*.gitlab-ci.yml' --name 'ci/pipeline.yml' .

# aligned table view, easier to scan when there are many findings
glsec --format table .gitlab-ci.yml

# JSON output for machine consumption
glsec --format json .gitlab-ci.yml

# SARIF output for GitHub Code Scanning / GitLab SAST
glsec --format sarif .gitlab-ci.yml > gl.sarif

# JSON/SARIF carry OWASP CICD-SEC, CWE, and OWASP ASVS V14 mappings per finding

# Code Climate output for GitLab Code Quality (inline MR findings, works on all tiers)
glsec --format codeclimate .gitlab-ci.yml > gl-code-quality.json

# treat warn findings as hard failures (exit 1)
glsec --strict .gitlab-ci.yml

# advisory mode: always exit 0, even with findings
glsec --no-exit-codes .gitlab-ci.yml

# exclude a file or directory from scanning
glsec --exclude vendor/ .gitlab-ci.yml

# run only specific rules (comma-separated or repeated)
glsec --only GL001,GL003 .gitlab-ci.yml

# skip specific rules
glsec --skip GL008,GL022 .gitlab-ci.yml

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

# gate MRs on "don't make it worse": fail only on findings not in the baseline
glsec --new-only .gitlab-ci.yml                       # diff against .glsec-ignore
glsec --new-only --baseline main.json .gitlab-ci.yml  # diff against a saved JSON snapshot
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No `error`-severity findings (warn-only findings exit 0 by default) |
| 1 | One or more `error` findings; or any finding when `--strict` is set |
| 2 | Usage error or file could not be parsed |

Use `--strict` to treat `warn` findings as hard failures (exit 1). Use `--no-exit-codes` to always exit 0 regardless of findings (advisory/informational mode). All flags can also be set in `.glsec.yml`:

```yaml
strict: true        # warn findings cause exit 1
no-exit-codes: true # never exit 1 (overrides strict)

exclude_paths:
  - legacy/.gitlab-ci.yml
  - infra/old-pipelines/**
  - vendor/

recursive_patterns:    # extra CI-config names/paths for --recursive (default: .gitlab-ci.yml)
  - '*.gitlab-ci.yml'   # no "/" → matched against the basename
  - ci/pipeline.yml     # contains "/" → matched against the path relative to each scanned dir
```

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

## Rules

78 rules across 8 [OWASP CI/CD security categories](https://owasp.org/www-project-top-10-ci-cd-security-risks/):

| Category | OWASP | Rules |
|----------|-------|-------|
| Credential Hygiene | CICD-SEC-6 | GL004, GL005, GL006, GL010, GL014, GL018, GL021, GL027, GL029, GL032, GL033, GL035, GL036, GL037, GL038, GL040, GL052, GL059, GL062, GL066, GL068, GL070, GL073 |
| Dependency & Image Pinning | CICD-SEC-3 | GL001, GL003, GL011, GL016, GL022, GL023, GL026, GL046, GL064, GL069, GL072, GL075 |
| Component & Third-Party Integrity | CICD-SEC-4, CICD-SEC-8 | GL002, GL007, GL015, GL025, GL041, GL044, GL051, GL053, GL065, GL067, GL078 |
| Supply Chain Integrity | CICD-SEC-9 | GL020, GL045 |
| Pipeline Flow & Access Control | CICD-SEC-1, CICD-SEC-5 | GL008, GL009, GL012, GL013, GL017, GL019, GL034, GL039, GL043, GL055, GL071, GL074 |
| Insecure Configuration | CICD-SEC-7 | GL024, GL028, GL030, GL031, GL042, GL047, GL048, GL049, GL050, GL054, GL056, GL057, GL058, GL060, GL061, GL063, GL076, GL077 |

→ **[Full rule reference with descriptions and examples](docs/rules.md)**

**Not covered:** [CICD-SEC-2](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management) (Identity & Access Management) and [CICD-SEC-10](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-And-Visibility) (Insufficient Logging & Visibility) are not detectable from static `.gitlab-ci.yml` analysis — they require platform-level context such as GitLab group/project settings, audit logs, or API access.

### Shell assumptions

The script-analysis rules (e.g. GL002, GL011, GL024, GL025, GL047, GL048, GL050) assume **POSIX shell** (`bash`/`sh`) semantics — the default for Linux and macOS runners. PowerShell pipelines on Windows runners use different syntax (`$env:VAR` instead of `$VAR`, `Invoke-WebRequest` instead of `curl`, etc.), so these rules will not match them. **A Windows-runner job that emits no findings has not been meaningfully checked for shell issues** — don't treat the absence of findings there as a clean bill of health.

### Reusable configuration

glsec resolves YAML anchors/aliases (`&anchor` / `*alias`, handled natively by the parser) and GitLab [`!reference` tags](https://docs.gitlab.com/ci/yaml/yaml_optimization/#reference-tags) that point within the same file. Content pulled in via `!reference` is analysed as if it were inlined into the referencing job, so issues hidden in shared `.template` blocks are caught. References that resolve into `include:`d files are not yet expanded.

## ShellCheck integration

glsec can optionally pass `script:`, `before_script:`, and `after_script:` blocks to [ShellCheck](https://www.shellcheck.net/) for deeper shell analysis. This is **opt-in** and requires ShellCheck to be installed separately.

Enable it in `.glsec.yml`:

```yaml
shellcheck:
  enabled: true
  path: /usr/bin/shellcheck  # optional — defaults to PATH lookup
```

ShellCheck findings are reported alongside GL findings and use `SC` rule IDs:

```
WARN   .gitlab-ci.yml:12  SC2086  [build]  Double quote to prevent globbing and word splitting.
```

If the ShellCheck binary is not found, glsec prints a warning to stderr and continues scanning normally.

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
    rev: v1.9.0
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

This adds:

- **`/glsec:scan`** — a command that runs glsec over the project and has Claude explain and remediate each finding.
- **An edit hook** — after Claude writes or edits a `.gitlab-ci.yml` (or a `.gitlab/*.yml`) file, glsec scans it automatically and surfaces any findings.

No Go toolchain is required: the plugin bundles a small POSIX wrapper that resolves a `glsec` binary in order of preference — an existing one on your `PATH`, a cached download, or the prebuilt release asset (downloaded and **verified against `checksums.txt`**, then cached). Supported on **Linux and macOS** (amd64/arm64); the wrapper needs `curl` or `wget`, and the edit hook needs `jq`. On other platforms it prints an install hint instead.

---

## CI integration

> **Runnable examples for every pattern below:** [gitlab.com/glsec-io/examples](https://gitlab.com/glsec-io/examples) — [Catalog component](https://gitlab.com/glsec-io/examples/component) · [Catalog + Code Quality](https://gitlab.com/glsec-io/examples/component-code-quality) · [Docker image](https://gitlab.com/glsec-io/examples/docker) · [Binary download](https://gitlab.com/glsec-io/examples/binary)

### GitLab CI Catalog component (recommended)

Use the official component from the [GitLab CI Catalog](https://gitlab.com/explore/catalog/glsec-io/glsec) — no need to manage image pins or script wiring yourself:

```yaml
include:
  - component: gitlab.com/glsec-io/glsec/glsec@v1.0.9

stages:
  - test
```

For inline findings on merge request diffs, add the `glsec-code-quality` template — works on **all GitLab tiers**, no Ultimate required:

```yaml
include:
  - component: gitlab.com/glsec-io/glsec/glsec-code-quality@v1.0.9

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
    name: ghcr.io/glsec/glsec:1.9.0
    entrypoint: [""]
  script:
    - glsec .gitlab-ci.yml
```

The `entrypoint: [""]` override is required: the image sets `ENTRYPOINT ["glsec"]` for `docker run` convenience, which conflicts with GitLab Runner's shell wrapper. Pin to a specific tag (`1.9.0`, not `:latest`) for reproducible pipelines.

### GitLab CI — binary download

For pipelines that cannot pull from GHCR:

```yaml
variables:
  GLSEC_VERSION: "1.9.0"

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

### GitLab SAST integration

Publish findings to GitLab's Security Dashboard by emitting SARIF and exposing it as a SAST report artifact:

```yaml
glsec:
  stage: test
  image:
    name: ghcr.io/glsec/glsec:1.9.0
    entrypoint: [""]
  script:
    - glsec --format sarif .gitlab-ci.yml > glsec.sarif || true
  artifacts:
    reports:
      sast: glsec.sarif
```

Findings appear in the pipeline Security tab and the project Security Dashboard. Use `|| true` to prevent the glsec job itself from blocking the pipeline — the SAST report is uploaded regardless.

### GitLab Code Quality integration

Show findings **inline on merge request diffs** using GitLab's Code Quality widget — works on all GitLab tiers (no Ultimate required, unlike SAST). The easiest path is the `glsec-code-quality` template from the [Catalog component](#gitlab-ci-catalog-component-recommended) above. The equivalent manual setup:

```yaml
glsec:
  stage: test
  image:
    name: ghcr.io/glsec/glsec:1.9.0
    entrypoint: [""]
  script:
    - glsec --format codeclimate .gitlab-ci.yml > gl-code-quality.json || true
  artifacts:
    reports:
      codequality: gl-code-quality.json
```

Severity mapping (glsec → Code Climate): `error` → `critical`, `warn` → `major`, `info` → `info`.

### GitHub Actions

```yaml
- name: Run glsec
  run: |
    curl -sSLO https://github.com/glsec/glsec/releases/latest/download/glsec_linux_amd64.tar.gz
    tar xzf glsec_linux_amd64.tar.gz
    ./glsec .gitlab-ci.yml
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0
