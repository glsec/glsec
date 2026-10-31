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
  - component: gitlab.com/glsec-io/glsec/glsec@v1.0.27
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
curl -sSLO https://github.com/glsec/glsec/releases/download/v1.25.0/glsec_1.25.0_linux_amd64.tar.gz
tar xzf glsec_1.25.0_linux_amd64.tar.gz
./glsec --version
```

**Docker:**

```sh
docker run --rm -v "$PWD:/src:ro" -w /src ghcr.io/glsec/glsec:1.25.0
```

Without a file argument glsec scans `.gitlab-ci.yml` in the mounted directory.

To check the download before running it, see [Verifying a release](#verifying-a-release).

## Usage

```sh
glsec .gitlab-ci.yml                      # scan a file: exit 1 on error findings, 0 if clean, 2 if it can't be scanned
glsec --recursive .                       # every .gitlab-ci.yml in a tree
glsec --format codeclimate .gitlab-ci.yml > gl-code-quality.json   # also json, sarif, junit, gitlab-sast, table
glsec --generate-ignore .gitlab-ci.yml    # baseline the existing findings
glsec --new-only .gitlab-ci.yml           # then fail only on new ones
glsec explain GL001                       # what a rule checks and how to fix it
```

**[Using glsec](docs/usage.md)** describes every flag and the rest of the command line:
[report formats and templates](docs/usage.md#report-templates), [exit codes](docs/usage.md#exit-codes), [configuration](docs/usage.md#configuration-file), [baselines](docs/usage.md#baseline-diff---new-only), [suppressions](docs/usage.md#suppressions), [scanning repositories you don't trust](docs/usage.md#scanning-repositories-you-dont-trust), the [result cache](docs/usage.md#result-cache), [secrets in reports](docs/usage.md#secrets-in-reports), and how glsec reads [shell](docs/usage.md#shell-assumptions), [`rules:` variables](docs/usage.md#variables-in-rules) and [anchors, `!reference` and includes](docs/usage.md#reusable-configuration).

### Configuration file

glsec reads `.glsec.yml` from the working directory, or the file passed with `--config`. [`docs/glsec.example.yml`](docs/glsec.example.yml) shows every key, and [`schema/glsec.schema.json`](schema/glsec.schema.json), listed in the [SchemaStore](https://www.schemastore.org) catalog, gives editors completion and validation. Details: [Configuration file](docs/usage.md#configuration-file).

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

How glsec reads YAML anchors, `!reference`, `include: local` and child pipelines: [Reusable configuration](docs/usage.md#reusable-configuration).

## ShellCheck integration

glsec can pass `script:`, `before_script:` and `after_script:` to [ShellCheck](https://www.shellcheck.net/) for deeper shell analysis (`shellcheck: {enabled: true}` in `.glsec.yml`). See [ShellCheck integration](docs/shellcheck.md).

## CI integration

```yaml
include:
  - component: gitlab.com/glsec-io/glsec/glsec@v1.0.27
```

**[CI integration](docs/ci-integration.md)** covers the [GitLab CI/CD Catalog component](docs/ci-integration.md#gitlab-ci-catalog-component-recommended), the [Docker image](docs/ci-integration.md#gitlab-ci--docker-image) and [binary](docs/ci-integration.md#gitlab-ci--binary-download) in GitLab CI, findings in merge requests through [Code Quality](docs/ci-integration.md#gitlab-code-quality-integration) and the [vulnerability report](docs/ci-integration.md#gitlab-vulnerability-report-and-security-widget-ultimate), the [pipeline inventory](docs/ci-integration.md#pipeline-inventory-cyclonedx), [GitHub Actions](docs/ci-integration.md#github-actions) and [MegaLinter](docs/ci-integration.md#megalinter). Runnable examples: [gitlab.com/glsec-io/examples](https://gitlab.com/glsec-io/examples).

## Pre-commit hook

glsec ships a [pre-commit](https://pre-commit.com/) hook, as a Go build, for a binary on `PATH` or with Docker. See [Pre-commit hook](docs/ci-integration.md#pre-commit-hook).

## Claude Code plugin

glsec ships as a [Claude Code](https://claude.com/claude-code) plugin with a `/glsec:scan` command and a hook that scans `.gitlab-ci.yml` after each edit. See [Claude Code plugin](docs/ci-integration.md#claude-code-plugin).

## Verifying a release

Releases and the container image are signed through Sigstore and carry SLSA Build Level 3 provenance, and release builds are reproducible. How to check a download, the image and the checksums, and how to rebuild a release: [Verifying a release](docs/verifying-releases.md).


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
