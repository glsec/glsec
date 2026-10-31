# Architecture

glsec is a single Go binary that reads GitLab CI configuration files and reports findings. It has no server component, makes no network calls and keeps no state except an optional result cache. This document describes how a scan works, who and what takes part in building and shipping glsec, and what glsec defends against.

## A scan

```text
files ─▶ resolve targets ─▶ parse ─▶ validate ─▶ follow includes and child pipelines
                                                        │
          exit code ◀─ output ◀─ baseline diff ◀─ suppressions ◀─ rules (+ ShellCheck)
```

1. **Resolve targets** (`cmd/glsec`). Command-line arguments become a list of files: literal paths, globs, a directory's `.gitlab-ci.yml`, `--recursive` directory walks, stdin (`-`, named with `--stdin-filename`), or `.gitlab-ci.yml` in the working directory. `--exclude` and `exclude_paths` drop files here.
2. **Parse** (`internal/parser`). Each file is parsed with `gopkg.in/yaml.v3` into a node tree that keeps line and column numbers. A key that appears twice in one mapping keeps only its last value, as in GitLab, and the dropped keys are recorded for GL087. YAML anchors, aliases and merge keys are resolved within a fixed node budget, and same-file `!reference` tags are expanded. Component templates with a `spec:` header are recognised; after such a header only the last document is scanned, as GitLab runs only that one. A top-level `default:` or `workflow:` that holds job keywords is marked as the job GitLab makes of it, and `run:` steps are read like `script:`. For folded multi-line scalars the parser records the source line of each part of the value, so findings inside them point at the right line.
3. **Validate** (`internal/validate`). A file that can't be read or parsed, isn't a top-level mapping or has no GitLab CI content is a scan error: the other files are still scanned, the reports name the failed file, and glsec exits 2.
4. **Follow includes and child pipelines** (`cmd/glsec`). Files named in `include: local` (wildcards included, at most 150 per pattern) and in `trigger: include:` are parsed too, recursively, with paths from the repository root. The files of one pipeline are checked with each other's global keywords and hidden jobs, as GitLab merges them (`withPipelineContext`); a child pipeline is a pipeline of its own. Remote, project, template and component includes are not fetched.
5. **Rules** (`rules`, `internal/rule`). Every enabled rule walks the node tree and returns findings with rule ID, severity, file, line and message. Configuration (`internal/config`, read from `.glsec.yml`) and flags decide which rules run (`--only`, `--skip`, OWASP filters, `--gitlab-version`). If enabled, ShellCheck (`internal/shellcheck`) checks script blocks as an external process, with a 30-second limit per job; a ShellCheck that fails or runs too long is a scan error, and only a missing binary is a warning.
6. **Suppressions** (`internal/suppress`). Inline `# glsec:ignore` comments and `.glsec-ignore` entries remove findings, honouring expiry dates; `--require-ignore-reason` turns a missing reason into exit 2. Duplicate findings from shared anchors are merged (`internal/finding`).
7. **Baseline** (`internal/baseline`). With `--new-only`, findings already in a baseline file are dropped.
8. **Output** (`internal/output`). Findings are written as text, table, JSON, SARIF, GitLab Code Quality, JUnit, a GitLab SAST report or through a Go template to stdout, with the scan errors in the format's own field. Secret values in messages and source lines are masked first (`internal/redact`) unless `--no-redact` is given. The exit code is 0, 1 for error findings (or warn findings with `--strict`), or 2 for usage, scan and policy errors.

Results can be cached per input (`internal/cache`, under `$XDG_CACHE_HOME/glsec`), keyed on the glsec version, the date, the GitLab version, every input file, the configuration, `.glsec-ignore`, the excluded paths and the selected rules. The cache is off in CI (`CI=true`) unless `--cache` is given, and for stdin, `--no-ignores`, `--new-only`, `--generate-ignore` and `require_ignore_reason`.

### Interfaces

glsec's external interfaces are the command line, `.glsec.yml`, `.glsec-ignore`, inline suppression comments, the output formats and the exit codes, all documented in [Using glsec](docs/usage.md), the `list`, `explain` and `inventory` (a CycloneDX bill of materials of the images and includes) subcommands, and the rule documentation in [docs/rules](docs/rules). Integrations wrap the same binary: the container image, the GitLab CI/CD Catalog component, the pre-commit hook, the GitHub Action example, and the Claude Code and MegaLinter plugins. It is distributed as release archives, the image, PyPI wheels, a Homebrew tap and through aqua and mise.

## Building and shipping

| Actor | Role |
|---|---|
| Maintainer | Merges pull requests into `main`, pushes release tags, points the Claude Code plugin at the new tag, releases the GitLab component |
| GitHub Actions | Runs CI on every pull request and push (tests on Linux, macOS and Windows, statement and branch coverage, lint, govulncheck, OSV-Scanner, dependency review, CodeQL, zizmor, cfgaudit, license headers, version pins, Trivy, hadolint, dockle; fuzzing and benchmarks for Go changes, GitLab CI Lint for fixtures, a link check for documentation changes); builds releases and images |
| `build-release.yml` / `build-image.yml` | Reusable workflows, called by `release.yml` and `docker.yml`, that build the archives with GoReleaser and the image with Docker and attest them; they sign the provenance (SLSA Build Level 3), and `build-image.yml` also signs the image with cosign and attaches its SBOM |
| Sigstore (Fulcio, Rekor) | Issues short-lived signing certificates and records signatures in a transparency log |
| GitHub Releases, `ghcr.io/glsec/glsec` | Distribute archives, checksums, SBOMs, attestation bundles and the image |
| PyPI | Distributes wheels that carry the release binary, checked against the release's checksums and provenance; `pypi.yml` uploads them through Trusted Publishing after the maintainer approves the `pypi` environment |
| GitLab (`glsec-io`) | Hosts the CI/CD Catalog component and the example repositories; `main` is protected there as on GitHub: merge requests only, after a passing pipeline |
| Dependabot | Proposes dependency updates as pull requests: Go modules, actions and CI tools after a 7-day cooldown, base images daily |

A release starts when the maintainer pushes a `vX.Y.Z` tag. `release.yml` and `docker.yml` refuse to run unless CI passed for that commit, then call the reusable build workflows. Release builds are reproducible: rebuilding a tag with the pinned GoReleaser and Go versions gives the published checksums.

The Claude Code plugin is installed from the marketplace in `.claude-plugin/marketplace.json`, which pins the plugin to the commit of a release tag (`ref` and `sha`). The release commit can't name its own SHA, so after tagging the maintainer moves the pin to the new tag in a follow-up pull request. Until then plugin users stay on the previous release.

## Threat model

glsec reads pipeline files that attackers may write (a fork's merge request is a core use case), runs inside CI with whatever access that job has, and is itself a supply-chain dependency of its users. The [trust boundary in SECURITY.md](SECURITY.md#trust-boundary) lists what counts as a vulnerability. The most likely and most damaging problems, and how glsec counters them:

| Threat | Impact | Countermeasures |
|---|---|---|
| A crafted pipeline file makes glsec hang or exhaust memory (alias bombs, nested `!reference` tags, long pipelines or `extends:` chains, huge files) | A CI job that never finishes or a runner that runs out of memory | Alias and `!reference` expansion share a fixed node budget; `extends:` is followed at most 11 levels deep, as in GitLab; rules avoid work that grows faster than the input; Go's linear-time RE2 regex engine; continuous fuzzing of the parser, the rules and whole scans. Before 1.22.0 nested `!reference` tags, GL083 and GL024 were not bounded ([GHSA-ggp8-xppq-737m](https://github.com/glsec/glsec/security/advisories/GHSA-ggp8-xppq-737m)) |
| A crafted repository makes glsec execute something | Code execution in the user's CI job or on a reviewer's machine | glsec never runs a shell and never evaluates pipeline content; the optional ShellCheck call passes arguments as a list and the script in a temporary file, and its path is never taken from a `.glsec.yml` that glsec finds in the scanned directory. Before 1.22.0 it was ([GHSA-pfj6-q8r7-c768](https://github.com/glsec/glsec/security/advisories/GHSA-pfj6-q8r7-c768)) |
| A crafted repository makes glsec read files outside it | Lines of other files on the runner in the job log | `include: local` and child pipeline paths, wildcard matches and the pipeline file itself are resolved, including symbolic links, and refused when they leave the repository ([GHSA-7vgh-xjjq-3wgv](https://github.com/glsec/glsec/security/advisories/GHSA-7vgh-xjjq-3wgv), [GHSA-ggp8-xppq-737m](https://github.com/glsec/glsec/security/advisories/GHSA-ggp8-xppq-737m)) |
| Output that breaks out of its format (SARIF, JSON, JUnit, Code Quality, GitLab SAST) and injects into the tool that reads it, or text output that forges lines in a terminal or job log | Misleading or injected content in security dashboards; hidden findings or a fake clean result in a job log | The built-in machine-readable formats are produced by Go's `encoding/json` / `encoding/xml` encoders, which escape all values; `--format template` takes its template from the command line only and offers escape functions per output syntax; text and table output and messages on stderr escape control characters, line separators and bidirectional overrides from the scanned file |
| A secret in the scanned file is repeated in a report | The secret reaches job logs, artifacts and code scanning, which are often more widely readable than the repository | Known token formats, URL passwords, authorization headers and secret-named variables are masked in every format before writing; `--no-redact` is a command-line flag only |
| A false negative hides a real problem | Users trust a pipeline that is unsafe | Unit tests for each rule including where it must stay silent, a pre-release scan of over 1,000 real pipelines, false-negative issue form |
| A suppression or baseline hides more than intended | Real findings silently dropped | Suppressions match by rule and line; expired suppressions report the finding again; `--no-ignores` audit mode |
| A compromised dependency or build step | A backdoored binary or image reaches users | One direct Go dependency; actions pinned by SHA; Dependabot with cooldown; govulncheck; OSV-Scanner, including known malicious packages; dependency review with a license allow list; harden-runner egress allow lists on the release jobs; signed SLSA Build Level 3 provenance; reproducible builds; Trivy, hadolint and dockle on the image |
| A compromised maintainer account | Malicious commits or releases | Two-factor authentication required on the GitHub organization; protected `main` (pull requests and required checks, also for admins); releases only from tags whose CI passed |

Out of scope: an attacker who controls the machine glsec runs on, and misconfigurations that glsec correctly reports in a user's pipeline.

## Assurance case

The claim: glsec can scan pipeline files written by an attacker, inside the attacker's merge request pipeline, without being made to do anything but report findings. The argument has four parts. Three published advisories, listed in part 3 and in [SECURITY.md](SECURITY.md#published-vulnerabilities), were gaps in this claim; each is fixed and covered by tests.

**1. The threats are known.** The threat model above lists what an attacker can try against glsec and against its supply chain, and [SECURITY.md](SECURITY.md#trust-boundary) draws the trust boundary: pipeline files and everything else in the scanned repository, including its `.glsec.yml`, are untrusted input; the user who runs glsec, the options and configuration they pass, and the machine it runs on are trusted.

**2. The design follows secure-design principles** ([Saltzer and Schroeder](https://doi.org/10.1109/PROC.1975.9939)):

| Principle | How glsec applies it |
|---|---|
| Economy of mechanism | One static binary, one direct Go dependency (`gopkg.in/yaml.v3`), no plugins, no embedded interpreter. The whole scan is the pipeline in [A scan](#a-scan) |
| Fail-safe defaults | Input that isn't a valid GitLab CI file, and a ShellCheck that fails, make the scan exit 2 and are named in the reports instead of passing silently. `include: local` and child pipeline paths that leave the repository are skipped, and a pipeline file that is a symbolic link out of its directory stops the scan. Remote includes are never fetched. A `.glsec.yml` found in the scanned directory cannot set the ShellCheck binary |
| Complete mediation | Every file, including included files and child pipelines, goes through the same parser, alias budget and validation before any rule sees it |
| Least privilege | No network access, no shell, no writes except the result cache (directory `0700`, files `0600`, written by atomic rename; not used when it lies inside the scanned repository or others can write to it), ShellCheck's temporary file and files the user asks for. The container image runs as a non-root user. Release workflows get only the token permissions each job needs |
| Least common mechanism | ShellCheck, when enabled, runs as a separate process with its arguments as a list; the script goes to a temporary file, never onto a command line |
| Open design | Source, rules, threat model and build are public; releases are reproducible, so anyone can check that a binary comes from the tagged source |
| Psychological acceptability | Safe behaviour needs no configuration. Suppressions are visible in the file, can expire, and can be required to carry a reason |

**3. Common weaknesses are countered** where they apply to a tool like glsec:

| Weakness | Countermeasure |
|---|---|
| [CWE-22](https://cwe.mitre.org/data/definitions/22.html) Path traversal | `include: local` and child pipeline paths are resolved from the repository root, including symbolic links, and paths outside it are skipped. This was a vulnerability before 1.21.1 ([GHSA-7vgh-xjjq-3wgv](https://github.com/glsec/glsec/security/advisories/GHSA-7vgh-xjjq-3wgv)); a test now covers `..`, absolute and symlinked paths |
| [CWE-59](https://cwe.mitre.org/data/definitions/59.html) Link following | The pipeline file is resolved like a child pipeline path and refused when a symbolic link leads out of its directory. This was a vulnerability before 1.22.0 ([GHSA-ggp8-xppq-737m](https://github.com/glsec/glsec/security/advisories/GHSA-ggp8-xppq-737m)); tests cover links that stay inside and links that leave |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) OS command injection | glsec never starts a shell and never evaluates pipeline content. The only external process, ShellCheck, gets fixed arguments |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) / [CWE-776](https://cwe.mitre.org/data/definitions/776.html) Resource exhaustion, recursive entity expansion | YAML alias and `!reference` expansion share a fixed node budget; `extends:` is followed at most 11 levels deep and child pipeline chains with cycle detection |
| [CWE-407](https://cwe.mitre.org/data/definitions/407.html) Inefficient algorithmic complexity | Rules look jobs up in a map and check a shell pipeline in one pass. Before 1.22.0, GL083 was quadratic and GL024 cubic in the size of a crafted file ([GHSA-ggp8-xppq-737m](https://github.com/glsec/glsec/security/advisories/GHSA-ggp8-xppq-737m)); tests with a time limit cover both |
| [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) Inefficient regular expressions | All rules use Go's RE2-based `regexp`, which runs in linear time |
| [CWE-116](https://cwe.mitre.org/data/definitions/116.html) / [CWE-117](https://cwe.mitre.org/data/definitions/117.html) Improper output encoding, log injection | JSON, SARIF, Code Quality, JUnit and GitLab SAST output is produced by Go's `encoding/json` and `encoding/xml`, which escape every value; a `--format template` template escapes with the functions glsec provides for CSV, Markdown and XML. Text and table output and messages on stderr escape control characters, line separators and bidirectional overrides; before 1.22.0 they printed them raw ([GHSA-ggp8-xppq-737m](https://github.com/glsec/glsec/security/advisories/GHSA-ggp8-xppq-737m)) |
| [CWE-377](https://cwe.mitre.org/data/definitions/377.html) Insecure temporary files | Temporary files are created with `os.CreateTemp` (unique name, owner-only permissions) and removed after use |
| [CWE-494](https://cwe.mitre.org/data/definitions/494.html) / [CWE-829](https://cwe.mitre.org/data/definitions/829.html) Untrusted downloads and inclusions | glsec downloads and includes nothing at runtime, and runs no program named by the scanned repository: before 1.22.0, a `.glsec.yml` in it could set the ShellCheck binary ([GHSA-pfj6-q8r7-c768](https://github.com/glsec/glsec/security/advisories/GHSA-pfj6-q8r7-c768)). Its own releases are signed with SLSA Build Level 3 provenance and can be verified and rebuilt ([Verifying a release](docs/verifying-releases.md)) |
| [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) Vulnerable third-party components | govulncheck, OSV-Scanner and dependency review run on every change and block merges; Dependabot keeps dependencies current |

**4. The evidence is checked continuously.** Unit tests cover every rule, including where it must stay silent. Native Go fuzzing runs the parser, the rules and whole scans on every change to Go code or fixtures and for 10 minutes every week. golangci-lint with gosec, zizmor for the workflows, and Trivy, hadolint and dockle for the image are required checks; CodeQL runs on every change as well. Before each release, new and changed rules are run against over 1,000 real pipelines to find false positives.
