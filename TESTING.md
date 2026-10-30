# Testing glsec

glsec decides what a security review of a pipeline reports, so a wrong answer costs in both directions: a false positive teaches people to ignore it, a missed finding gives false confidence. This page is the overview of how glsec is tested and what each layer protects against. How to run each one is in [CONTRIBUTING.md](CONTRIBUTING.md).

## Principles

- **Every bug leaves a test behind.** A false positive or a missed finding becomes a case in the regression corpus. A crash found by fuzzing becomes a seed input. A parser difference becomes a parser test.
- **Equivalent input, equivalent output.** Two pipelines that mean the same to GitLab must give the same findings, however the YAML is written.
- **GitLab is the reference.** Fixtures and documentation examples are complete pipelines that GitLab's own CI Lint accepts, not fragments that only glsec understands.
- **When unsure, stay quiet.** A rule that can't see everything a job inherits (an `extends:` from another file, an unresolved variable) skips the job rather than guess. Tests cover both the finding and the case where the rule must stay silent.
- **All platforms count the same.** The suite runs on Linux, macOS and Windows; path handling, line endings and file permissions differ between them.

## Layers

| Layer | Protects against | Runs |
|---|---|---|
| [Unit tests](CONTRIBUTING.md#step-5--write-unit-tests) per rule and package | wrong findings, wrong severity or message, missed edge cases | every pull request |
| [Consistency tests](CONTRIBUTING.md#step-4--satisfy-the-consistency-tests) | a rule without fixture, docs page, OWASP or CWE mapping; doc examples that don't trigger, or safe examples that do | every pull request |
| [Fixtures](CONTRIBUTING.md#fixture-validation), checked against the GitLab CI schema and GitLab's CI Lint API | test pipelines and doc examples GitLab would reject | every pull request (the CI Lint part after merge for forks) |
| [Regression corpus](CONTRIBUTING.md#regression-corpus) with snapshot files | a fixed false positive or missed finding coming back | every pull request |
| [Metamorphic test](CONTRIBUTING.md#metamorphic-test) | rules that match on how the YAML is written instead of what it means (quoting, flow style, CRLF, job order, anchors, `extends:`) | every pull request |
| [Fuzzing](CONTRIBUTING.md#fuzzing) of the parser, the rules and a whole scan | crashes and hangs on hostile or broken YAML | short runs on pull requests and `main`, longer runs weekly |
| [Linear scaling test](CONTRIBUTING.md#performance) | a rule whose run time grows faster than the pipeline | every pull request |
| [Benchmarks](CONTRIBUTING.md#performance), pull request against its base | allocation regressions; time is reported | pull requests; history recorded on `main` |
| Race detector, Linux/macOS/Windows | data races, platform-specific bugs | every pull request |
| [Coverage](CONTRIBUTING.md#coverage): statement and branch coverage with thresholds | code no test exercises | every pull request |
| Reproducible build | a release binary that differs from what the source builds | pull requests touching the build, `main` |
| Package smoke tests: the image, each release archive and each PyPI wheel installed and run on its platform, version checked and a fixture scanned | a package that doesn't start, reports the wrong version or finds nothing | the image on every pull request and before it is pushed; archives with the reproducible build; wheels before the PyPI upload |
| Static analysis: [golangci-lint](CONTRIBUTING.md#linting), CodeQL, govulncheck, dependency and workflow scanners | bugs and vulnerabilities in the code, its dependencies and its CI | every pull request, CodeQL also weekly |
| Real pipelines: new rules against public pipelines, the parser against GitLab's CI Lint ([`ci-lint-diff.py`](CONTRIBUTING.md#fixture-validation)) | false positives that crafted fixtures don't show; files GitLab runs but glsec can't scan | before each release, see [RELEASING.md](RELEASING.md) |

Scheduled jobs also watch what glsec depends on from outside: the example projects' version pins, the CI/CD Catalog list GL064 compares against, new releases of the security frameworks glsec maps to, and the keywords in GitLab's CI schema, so a new keyword doesn't go unnoticed by the rules. They open an issue when something drifts.

## Adding a rule

A new rule needs unit tests for the finding and for the cases it must not report, a fixture, and a docs page whose trigger and safe examples the consistency tests run. The metamorphic test then runs it on every rewrite of every fixture without any extra work. The steps are in [How to add a rule](CONTRIBUTING.md#how-to-add-a-rule).
