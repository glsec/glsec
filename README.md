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
| [GL010](docs/rules/GL010.md) | `warn`  | `trigger: forward: pipeline_variables: true` leaks secrets to downstream pipeline (GitLab ≥ 14.9) |
| [GL011](docs/rules/GL011.md) | `error` | Download-and-execute pattern in script (`curl \| bash`, `wget \| sh`) |
| [GL012](docs/rules/GL012.md) | `warn`  | `when: always` on a deploy/release job bypasses upstream quality gates |
| [GL013](docs/rules/GL013.md) | `warn`  | Production deploy job has no `rules:` or `only:` branch restriction |
| [GL014](docs/rules/GL014.md) | `warn`  | `dotenv` artifact captures all environment variables including secrets (GitLab ≥ 12.9) |
| [GL015](docs/rules/GL015.md) | `warn`  | Docker image tag built from user-controlled variable (`$CI_COMMIT_REF_SLUG` etc.) |
| [GL016](docs/rules/GL016.md) | varies  | HTTP instead of HTTPS (`include:remote`, scripts, variables) |
| [GL017](docs/rules/GL017.md) | `warn`  | Deploy/publish job has no `tags:` — can run on any runner including untrusted self-hosted |
| [GL018](docs/rules/GL018.md) | `warn`  | Secret variable re-exported at pipeline level — available to all jobs including untrusted ones |
| [GL019](docs/rules/GL019.md) | `warn`  | Deploy/publish job has no `resource_group:` — concurrent runs risk race conditions or partial deploys |
| [GL020](docs/rules/GL020.md) | `warn`  | File downloaded with `curl`/`wget` without checksum verification before execution |
| [GL021](docs/rules/GL021.md) | `warn`  | Secret variable value printed to job log via `echo`/`printf` |
| [GL022](docs/rules/GL022.md) | `warn`  | Package manager install without version pin or explicit update-to-latest in CI |
| [GL023](docs/rules/GL023.md) | `warn`  | Lockfile not enforced (`npm install` instead of `npm ci`, `yarn install` without `--frozen-lockfile`, etc.) |

Each rule page contains the full risk description, trigger examples, safe alternatives, and detection notes.

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
