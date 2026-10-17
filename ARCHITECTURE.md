# Architecture

glsec is a single Go binary that reads GitLab CI configuration files and reports findings. It has no server component, makes no network calls and keeps no state except an optional result cache. This document describes how a scan works, who and what takes part in building and shipping glsec, and what glsec defends against.

## A scan

```
files ─▶ resolve targets ─▶ parse ─▶ validate ─▶ follow child pipelines
                                                        │
          exit code ◀─ output ◀─ baseline diff ◀─ suppressions ◀─ rules (+ ShellCheck)
```

1. **Resolve targets** (`cmd/glsec`). Command-line arguments become a list of files: literal paths, globs, `--recursive` directory walks, or `.gitlab-ci.yml` in the working directory. `--exclude` and `exclude_paths` drop files here.
2. **Parse** (`internal/parser`). Each file is parsed with `gopkg.in/yaml.v3` into a node tree that keeps line and column numbers. YAML anchors, aliases and merge keys are resolved within a fixed node budget, and same-file `!reference` tags are expanded. Component templates with a `spec:` header are recognised.
3. **Validate** (`internal/validate`). A file that isn't a top-level mapping or has no GitLab CI content stops here with exit 2.
4. **Follow child pipelines** (`cmd/glsec`). Local files named in `trigger: include:` are parsed too, recursively, with paths from the repository root. Remote, project, template and component includes are not fetched.
5. **Rules** (`rules`, `internal/rule`). Every enabled rule walks the node tree and returns findings with rule ID, severity, file, line and message. Configuration (`internal/config`, read from `.glsec.yml`) and flags decide which rules run (`--only`, `--skip`, OWASP filters, `--gitlab-version`). If enabled, ShellCheck (`internal/shellcheck`) checks script blocks as an external process.
6. **Suppressions** (`internal/suppress`). Inline `# glsec:ignore` comments and `.glsec-ignore` entries remove findings, honouring expiry dates; `--require-ignore-reason` turns a missing reason into exit 2. Duplicate findings from shared anchors are merged (`internal/finding`).
7. **Baseline** (`internal/baseline`). With `--new-only`, findings already in a baseline file are dropped.
8. **Output** (`internal/output`). Findings are written as text, table, JSON, SARIF, GitLab Code Quality or JUnit to stdout. The exit code is 0, 1 for error findings (or any finding with `--strict`), or 2 for usage, parse and policy errors.

Results can be cached per input (`internal/cache`, under `$XDG_CACHE_HOME/glsec`), keyed on the glsec version, the date, every input file, the configuration and the selected rules.

### Interfaces

glsec's external interfaces are the command line, `.glsec.yml`, `.glsec-ignore`, inline suppression comments, the output formats and the exit codes, all documented in the [README](README.md#usage), and the rule documentation in [docs/rules](docs/rules). Integrations wrap the same binary: the container image, the GitLab CI/CD Catalog component, the pre-commit hook, the GitHub Action example, and the Claude Code and MegaLinter plugins.

## Building and shipping

| Actor | Role |
|---|---|
| Maintainer | Merges pull requests into `main`, pushes release tags, releases the GitLab component |
| GitHub Actions | Runs CI on every pull request and push (tests on Linux, macOS and Windows, lint, govulncheck, CodeQL, zizmor, fuzzing, Trivy, hadolint, dockle; a link check for documentation changes); builds releases and images |
| `build-release.yml` / `build-image.yml` | Reusable workflows that build the archives with GoReleaser and the image with Docker, and attest them; they sign the provenance (SLSA Build Level 3) |
| Sigstore (Fulcio, Rekor) | Issues short-lived signing certificates and records signatures in a transparency log |
| GitHub Releases, `ghcr.io/glsec/glsec` | Distribute archives, checksums, SBOMs, attestation bundles and the image |
| GitLab (`glsec-io`) | Hosts the CI/CD Catalog component and the example repositories |
| Dependabot | Proposes dependency updates as pull requests: Go modules, actions and CI tools after a 7-day cooldown, base images daily |

A release starts when the maintainer pushes a `vX.Y.Z` tag. `release.yml` and `docker.yml` refuse to run unless CI passed for that commit, then call the reusable build workflows. Release builds are reproducible: rebuilding a tag with the pinned GoReleaser and Go versions gives the published checksums.

## Threat model

glsec reads pipeline files that attackers may write (a fork's merge request is a core use case), runs inside CI with whatever access that job has, and is itself a supply-chain dependency of its users. The [trust boundary in SECURITY.md](SECURITY.md#trust-boundary) lists what counts as a vulnerability. The most likely and most damaging problems, and how glsec counters them:

| Threat | Impact | Countermeasures |
|---|---|---|
| A crafted pipeline file makes glsec hang or exhaust memory (alias bombs, deep nesting, huge files) | A CI job that never finishes or a runner that runs out of memory | Bounded alias expansion; Go's linear-time RE2 regex engine; continuous fuzzing of the parser, the rules and whole scans |
| A crafted file makes glsec execute something | Code execution in the user's CI job | glsec never runs a shell and never evaluates pipeline content; the optional ShellCheck call passes arguments as a list and the script in a temporary file |
| Output that breaks out of its format (SARIF, JSON, JUnit, Code Quality) and injects into the tool that reads it | Misleading or injected content in security dashboards | Every format is produced by Go's `encoding/json` / `encoding/xml` encoders, which escape all values |
| A false negative hides a real problem | Users trust a pipeline that is unsafe | Unit tests for each rule including where it must stay silent, a pre-release scan of over 1,000 real pipelines, false-negative issue form |
| A suppression or baseline hides more than intended | Real findings silently dropped | Suppressions match by rule and line; expired suppressions report the finding again; `--no-ignores` audit mode |
| A compromised dependency or build step | A backdoored binary or image reaches users | One direct Go dependency; actions pinned by SHA; Dependabot with cooldown; govulncheck; harden-runner egress allow lists on the release jobs; signed SLSA Build Level 3 provenance; reproducible builds; Trivy, hadolint and dockle on the image |
| A compromised maintainer account | Malicious commits or releases | Two-factor authentication required on the GitHub organization; protected `main` (pull requests and required checks, also for admins); releases only from tags whose CI passed |

Out of scope: an attacker who controls the machine glsec runs on, and misconfigurations that glsec correctly reports in a user's pipeline.
