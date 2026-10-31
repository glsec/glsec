# Testing glsec

glsec decides what a security review of a pipeline reports, so a wrong answer costs in both directions: a false positive teaches people to ignore it, a missed finding gives false confidence. This page is the overview of how glsec is tested and what each layer protects against. How to run each one is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Principles

- **Every bug leaves a test behind.** A false positive or a missed finding becomes a case in the regression corpus. A crash found by fuzzing becomes a seed input. A parser difference becomes a parser test.
- **Equivalent input, equivalent output.** Two pipelines that mean the same to GitLab must give the same findings, however the YAML is written.
- **GitLab is the reference.** Fixtures and documentation examples are complete pipelines that GitLab's own CI Lint accepts, not fragments that only glsec understands.
- **When unsure, stay quiet.** A rule that can't see everything a job inherits (an `extends:` from another file, an unresolved variable) skips the job rather than guess. Tests cover both the finding and the case where the rule must stay silent.
- **All platforms count the same.** The suite runs on Linux, macOS and Windows; path handling, line endings and file permissions differ between them.

## Layers

Each layer names what it protects against and when it runs, grouped by what it checks: [findings](#findings), [reports and configuration](#reports-and-configuration), [robustness and performance](#robustness-and-performance), [code health](#code-health), [supply chain and repository security](#supply-chain-and-repository-security), [packages and integrations](#packages-and-integrations), [documentation](#documentation), the checks [before each release](#before-each-release) and the [scheduled watches](#scheduled-watches).

### Findings

Whether glsec reports the right findings, and only those.

| Layer | Protects against | Runs |
|---|---|---|
| [Unit tests](CONTRIBUTING.md#step-5--write-unit-tests) per rule and package | wrong findings, wrong severity or message, missed edge cases | every pull request |
| Unit tests of the shared helpers: the shell parsing (`rules/shell.go`) and the inheritance, block-walking and position helpers (`rules/helpers.go`), each tested on its own (`*_unit_test.go`) | a bug in a building block that many rules use, shown at the helper instead of as many failing rule tests | every pull request |
| [Consistency tests](CONTRIBUTING.md#step-4--satisfy-the-consistency-tests) | a rule without fixture, docs page, OWASP or CWE mapping; doc examples that don't trigger, or safe examples that do | every pull request |
| [Fixtures](CONTRIBUTING.md#fixture-validation), checked against the GitLab CI schema and GitLab's CI Lint API | test pipelines and doc examples GitLab would reject | every pull request (the CI Lint part after merge for forks) |
| [Regression corpus](CONTRIBUTING.md#regression-corpus) with snapshot files | a fixed false positive or missed finding coming back | every pull request |
| [Metamorphic test](CONTRIBUTING.md#metamorphic-test) | rules that match on how the YAML is written instead of what it means (quoting, flow style, CRLF, job order, anchors, `extends:`) | every pull request |

### Reports and configuration

Whether the output stays readable for the tools that consume it, and existing findings keep their identity.

| Layer | Protects against | Runs |
|---|---|---|
| [Finding identity snapshot](CONTRIBUTING.md#finding-identity-snapshots) | a message, path, report identifier or baseline key change that silently makes existing findings appear new | every pull request |
| [Report schemas](CONTRIBUTING.md#report-schemas): golden SARIF, Code Quality, JUnit, GitLab SAST and CycloneDX reports, with findings and scan errors, checked against each format's schema | a report GitHub code scanning or GitLab rejects or reads only in part | every pull request |
| Config schema: `schema/glsec.schema.json` compared with the config parser and the rule list, checked against the JSON Schema metaschema, and the example `.glsec.yml` checked against it | an editor schema that rejects a valid `.glsec.yml` or accepts an invalid one | every pull request |

### Robustness and performance

| Layer | Protects against | Runs |
|---|---|---|
| [Fuzzing](CONTRIBUTING.md#fuzzing) of the parser, the rules and a whole scan | crashes and hangs on hostile or broken YAML | 45 s per target on pull requests and pushes to `main` that change Go code or fixtures, 10 minutes weekly |
| [Linear scaling test](CONTRIBUTING.md#performance) | a rule whose run time grows faster than the pipeline | every pull request |
| [Benchmarks](CONTRIBUTING.md#performance), pull request against its base | allocation regressions; time is reported | pull requests that change Go code; history recorded on `main` |
| Race detector, Linux/macOS/Windows | data races, platform-specific bugs | every pull request |
| Hardening tests of glsec itself | a scanned repository that makes glsec read or quote files outside it (symbolic links, child pipelines), plant cache entries, inject terminal escapes into the output, or hang it with a FIFO or a huge file; a detected secret printed back into a report instead of masked; and a ShellCheck that fails or hangs making the scan look clean | every pull request, as part of the unit and CLI tests |

### Code health

| Layer | Protects against | Runs |
|---|---|---|
| [Coverage](CONTRIBUTING.md#coverage): statement and branch coverage with thresholds | code no test exercises | every pull request |
| Static analysis of the code: [golangci-lint](CONTRIBUTING.md#linting) with gosec, CodeQL | bugs and insecure patterns in glsec's own code | every pull request, CodeQL also weekly |
| Unreachable code: [deadcode](https://pkg.go.dev/golang.org/x/tools/cmd/deadcode) from `main`, against the allowlist [`.github/deadcode-allow.txt`](.github/deadcode-allow.txt) (golangci-lint's `unused` covers unexported code) | exported functions nothing calls any more, such as a wrapper only tests use after a refactor, so the tests check a path production doesn't take; allowlist entries that went stale | every pull request |

### Supply chain and repository security

Whether glsec's own dependencies, workflows and releases can be trusted.

| Layer | Protects against | Runs |
|---|---|---|
| [Dependency checks](CONTRIBUTING.md#dependencies): govulncheck, OSV-Scanner, dependency review | a known vulnerability or malicious package in a Go module or one of the CI's Python tools; govulncheck reports only what glsec's code can reach | govulncheck and OSV-Scanner on every pull request and push, dependency review on pull requests; required checks |
| Workflow security: zizmor, cfgaudit and pinact on the GitHub Actions workflows | injection, excessive permissions, unpinned actions and dangerous triggers in glsec's own CI; pinact additionally fails when an action's version comment doesn't match its pinned SHA | every pull request |
| Sensitive paths gate ([`.github/scripts/sensitive-paths.sh`](.github/scripts/sensitive-paths.sh)) | an unreviewed change to files that reach plugin users and the published pre-commit and MegaLinter integrations, the release build and its signing keys, a maintainer's agent setup, or the rules of the other checks; the check fails until a maintainer sets the `sensitive-paths-reviewed` label. A new push removes the label, unless the change to the sensitive paths is the same as when it was reviewed | every pull request |
| Release gate: CI passed for the tagged commit, and the tag is signed by a key in [`.github/allowed_signers`](.github/allowed_signers) as listed on `main` | a release or image built from a commit CI didn't pass, from an unsigned tag, or from a tag someone signed without being a listed maintainer; nothing is built or published | every tag push, before the Release and Docker workflows build anything |
| Reproducible build | a release binary that differs from what the source builds | pull requests that change the build configuration, `go.mod`, `go.sum` or `cmd/` (tests excluded); every push to `main` |
| Container image: Trivy, hadolint, dockle | a fixable HIGH or CRITICAL vulnerability in the image, Dockerfile mistakes, an image that runs as root | every pull request |
| OpenSSF Scorecard | a regression in the repository's supply-chain practices (branch protection, pinning, token permissions, …), reported as a code scanning alert | weekly, on pushes to `main` and when branch protection changes |
| Repository checks: license headers (`reuse lint`), DCO sign-off, version pins that agree across README, docs and plugins, `go mod verify` and a tidy `go.mod` | a file without a license, an unsigned commit, a release bump that misses a pin, an unverified module | every pull request |

### Packages and integrations

| Layer | Protects against | Runs |
|---|---|---|
| Package smoke tests: the image, each release archive and each PyPI wheel installed and run on its platform, version checked and a fixture scanned | a package that doesn't start, reports the wrong version or finds nothing | the image on every pull request and before it is pushed; archives with the reproducible build; wheels before the PyPI upload |
| MegaLinter plugin: the plugin installed and run in MegaLinter | a plugin that doesn't install or doesn't report | pull requests and pushes that change the plugin, and each published release |

### Documentation

| Layer | Protects against | Runs |
|---|---|---|
| Link check of all Markdown files | dead links and anchors in the docs | pull requests that change Markdown, and weekly with an issue on failure |
| Markdown lint ([markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2), rules on structure and rendering only, see [`.markdownlint-cli2.jsonc`](.markdownlint-cli2.jsonc)); inline HTML in `docs/rules.md` and `docs/rules/`, which the website drops | tables that split into the wrong cells, lists and code blocks glued to a paragraph, code blocks without a language, skipped heading levels, broken in-page links; content that would silently vanish from glsec.github.io | pull requests and pushes to `main` that change Markdown |

### Before each release

Manual checks a maintainer runs before tagging, see [RELEASING.md](RELEASING.md).

| Layer | Protects against | Runs |
|---|---|---|
| Documentation review: the README, the pages in `docs/` and the project documents (CONTRIBUTING, ARCHITECTURE, SECURITY, TESTING, GOVERNANCE, RELEASING, ROADMAP) checked against the code, the workflows and the repository settings, with AI assistance; a maintainer verifies every reported mismatch | documentation that describes behaviour, checks, access or steps that no longer match the project | before each release, see [RELEASING.md](RELEASING.md) |
| Real pipelines: new rules against public pipelines, the parser against GitLab's CI Lint ([`ci-lint-diff.py`](CONTRIBUTING.md#fixture-validation)) | false positives that crafted fixtures don't show; files GitLab runs but glsec can't scan | before each release, see [RELEASING.md](RELEASING.md) |
| Precision of new and changed rules: 20 random findings from different projects judged in context, the rule's premise checked against a primary source (50 findings for a rule a publication quotes) | a rule that matches what its page says while the page is wrong, such as a premise GitLab or the runner already handles | before each release, see [RELEASING.md](RELEASING.md) |

### Scheduled watches

Scheduled jobs also watch what glsec depends on from outside: the example projects' version pins, the CI/CD Catalog list GL064 compares against, new releases of the security frameworks glsec maps to, and the keywords in GitLab's CI schema, so a new keyword doesn't go unnoticed by the rules. They open an issue when something drifts.

## Adding a rule

A new rule needs unit tests for the finding and for the cases it must not report, a fixture, and a docs page whose trigger and safe examples the consistency tests run. The metamorphic test then runs it on every rewrite of every fixture without any extra work. The steps are in [How to add a rule](CONTRIBUTING.md#how-to-add-a-rule).
