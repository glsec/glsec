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

# JSON output for machine consumption
glsec --format json .gitlab-ci.yml

# SARIF output for GitHub Code Scanning / GitLab SAST
glsec --format sarif .gitlab-ci.yml > gl.sarif

# treat warn findings as hard failures (exit 1)
glsec --strict .gitlab-ci.yml

# advisory mode: always exit 0, even with findings
glsec --no-exit-codes .gitlab-ci.yml

# exclude a file or directory from scanning
glsec --exclude vendor/ .gitlab-ci.yml

# baseline existing findings so only new violations are reported
glsec --generate-ignore .gitlab-ci.yml
glsec .gitlab-ci.yml  # now exits 0; new violations will be caught
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
```

## Rules

26 rules across 5 [OWASP CI/CD security categories](https://owasp.org/www-project-top-10-ci-cd-security-risks/):

| Category | OWASP | Rules |
|----------|-------|-------|
| Credential Hygiene | CICD-SEC-6 | GL002, GL004, GL006, GL010, GL014, GL018, GL021 |
| Dependency & Image Pinning | CICD-SEC-3 | GL001, GL003, GL015, GL022, GL023, GL026 |
| Supply Chain Integrity | CICD-SEC-9 | GL011, GL020, GL025 |
| Pipeline Flow & Access Control | CICD-SEC-1, CICD-SEC-5 | GL008, GL009, GL012, GL013, GL017, GL019 |
| Insecure Configuration | CICD-SEC-7 | GL005, GL007, GL016, GL024 |

→ **[Full rule reference with descriptions and examples](docs/rules.md)**

---

## CI integration

### GitLab CI — Docker image (recommended)

The fastest way: use the pre-built image from GHCR. No Go toolchain needed.

```yaml
glsec:
  stage: test
  image: ghcr.io/glsec/glsec:latest
  script:
    - glsec .gitlab-ci.yml
```

Pin to a specific release for reproducible pipelines:

```yaml
glsec:
  stage: test
  image: ghcr.io/glsec/glsec:0.1.0
  script:
    - glsec .gitlab-ci.yml
```

### GitLab CI — binary download

For pipelines that cannot pull from GHCR:

```yaml
glsec:
  stage: test
  image: alpine:3.19
  script:
    - |
      curl -sSLO https://github.com/glsec/glsec/releases/latest/download/glsec_linux_amd64.tar.gz
      echo "$(curl -sSL https://github.com/glsec/glsec/releases/latest/download/checksums.txt | grep glsec_linux_amd64.tar.gz)" | sha256sum -c
      tar xzf glsec_linux_amd64.tar.gz
    - ./glsec .gitlab-ci.yml
```

### GitHub Actions

```yaml
- name: Run glsec
  run: |
    curl -sSLO https://github.com/glsec/glsec/releases/latest/download/glsec_linux_amd64.tar.gz
    tar xzf glsec_linux_amd64.tar.gz
    ./glsec .gitlab-ci.yml
```

### SARIF upload to GitHub Code Scanning

```yaml
- name: Run glsec (SARIF)
  run: |
    curl -sSLO https://github.com/glsec/glsec/releases/latest/download/glsec_linux_amd64.tar.gz
    tar xzf glsec_linux_amd64.tar.gz
    ./glsec --format sarif .gitlab-ci.yml > glsec.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: glsec.sarif
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0
