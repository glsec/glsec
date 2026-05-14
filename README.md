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
# scan a file (exits 1 if findings, 0 if clean, 2 on error)
glsec .gitlab-ci.yml

# JSON output for machine consumption
glsec --format json .gitlab-ci.yml

# SARIF output for GitHub Code Scanning / GitLab SAST
glsec --format sarif .gitlab-ci.yml > gl.sarif
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | One or more findings |
| 2 | Usage error or file could not be parsed |

## Rules

| ID | Severity | Description |
|----|----------|-------------|
| [GL001](docs/rules/GL001.md) | `error` | Mutable image tag (`latest`, no tag, non-digest pin) |
| [GL002](docs/rules/GL002.md) | `warn`  | User-controlled CI variable used unquoted in script |
| [GL003](docs/rules/GL003.md) | `error` | Remote `include:` with mutable or missing `ref` |
| [GL004](docs/rules/GL004.md) | `warn`  | `CI_JOB_TOKEN` forwarded to a non-GitLab host |
| [GL005](docs/rules/GL005.md) | `warn`  | Sensitive file patterns in `artifacts:` or missing `expire_in` |
| [GL006](docs/rules/GL006.md) | `error` | Hardcoded secret in `variables:` block |
| [GL007](docs/rules/GL007.md) | `error` | CI variable interpolation in `image:` reference |
| [GL008](docs/rules/GL008.md) | `warn`  | `allow_failure: true` on a GitLab security scan job |
| [GL009](docs/rules/GL009.md) | `warn`  | Overly broad OIDC `id_tokens` audience (GitLab ≥ 15.7) |

Each rule page contains the full risk description, trigger examples, safe alternatives, and detection notes.

---

## CI integration

### GitLab CI

```yaml
glsec:
  stage: test
  image: golang:1.24-alpine
  script:
    - go install github.com/glsec/glsec@latest
    - glsec .gitlab-ci.yml
```

### GitHub Actions

```yaml
- name: Run glsec
  run: |
    go install github.com/glsec/glsec@latest
    glsec .gitlab-ci.yml
```

### SARIF upload to GitHub Code Scanning

```yaml
- name: Run glsec (SARIF)
  run: |
    go install github.com/glsec/glsec@latest
    glsec --format sarif .gitlab-ci.yml > glsec.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: glsec.sarif
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0
