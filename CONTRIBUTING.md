# Contributing to glsec

## Reporting a bug

Open an [issue](https://github.com/glsec/glsec/issues/new/choose) and pick the form that fits:

- **Bug**: glsec crashes, errors, or does something its documentation says it doesn't.
- **False positive**: a finding for something that is actually fine.
- **False negative or missing rule**: an insecure pattern glsec doesn't report.

Include your glsec version (`glsec --version`), the command or integration you use, and the smallest pipeline snippet that shows the problem, with anything private removed. A vulnerability in glsec itself goes through [private vulnerability reporting](https://github.com/glsec/glsec/security/advisories/new) instead; [SECURITY.md](SECURITY.md) explains what counts.

## Dev environment

**Requirements:** Go 1.26+

```sh
git clone https://github.com/glsec/glsec.git
cd glsec
go build ./...
go test ./...
```

No code generation — `go build` is all you need. The `Makefile` has shortcuts (`make build`, `make test`, `make lint`).

## Dependencies

glsec keeps its dependencies few and checked:

- **Go modules.** `go.mod` lists the direct dependencies (currently only `gopkg.in/yaml.v3`) and `go.sum` pins their hashes; CI runs `go mod verify` and fails if `go mod tidy` would change either file. A new dependency needs a reason in the pull request: prefer the standard library, and pick maintained, widely used modules.
- **Updates.** Dependabot proposes updates for Go modules, GitHub Actions, the CI's Python tools and the Docker base images. Version updates wait 7 days after an upstream release (`cooldown` in `.github/dependabot.yml`), the window in which a compromised release is usually caught; security updates and base images are not delayed. Updates go through the same pull request checks as any change.
- **Pinning.** GitHub Actions are pinned to commit SHAs, the CI's Python tools (zizmor, check-jsonschema, reuse) to versions with hashes (`.github/requirements/`), Docker base images to digests, and GoReleaser to an exact version.
- **Checks.** govulncheck and OSV-Scanner run on every pull request and push, and dependency review on every pull request; all three are required checks. OSV-Scanner covers `go.mod` and the CI's Python requirements against known vulnerabilities and known malicious packages. Trivy scans the container image.

What blocks a merge or a release:

- **Vulnerabilities.** Any known vulnerability, of any severity, in a dependency added or changed by a pull request; any vulnerability that govulncheck finds reachable from glsec's code; any OSV finding; any HIGH or CRITICAL finding in the image for which a fix exists. A finding that doesn't affect glsec (for example, unreachable code) may be accepted only with a written reason in the pull request and, once it reaches users, a VEX statement as described in [SECURITY.md](SECURITY.md#vulnerabilities-that-dont-affect-glsec).
- **Malicious packages.** Always. The dependency is removed, and if a release contained it, the release is withdrawn and a security advisory is published.
- **Licenses.** Dependencies must be under a permissive or weak-copyleft license compatible with glsec's Apache-2.0 license: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, PSF-2.0, Unlicense or 0BSD. Dependency review fails on any other license; adding one needs a maintainer decision, recorded in the pull request.

## Running tests

[TESTING.md](TESTING.md) gives the overview: which tests exist, what each protects against and when it runs.

```sh
go test ./...                   # all packages
go test -race ./...             # with race detector, as CI does on Linux, macOS and Windows
go test ./rules/... -v -run GL001  # single rule
```

### Report schemas

Each machine-readable format has a golden report in `internal/output/testdata/` (`sarif.golden.json`, `codequality.golden.json`, `junit.golden.xml`, `gitlab-sast.golden.json`) and the inventory one in `internal/inventory/testdata/`. The Go tests compare the writers' output with them, and CI validates them against the formats' schemas, pinned by URL and SHA-256: SARIF 2.1.0, GitLab's SAST report schema, the JUnit XSD of Jenkins' xUnit plugin and CycloneDX 1.6. GitLab publishes no schema for Code Quality; `codequality.schema.json` encodes the fields it documents as required. When a writer changes on purpose, regenerate the golden files and check the diff:

```sh
go test ./internal/output -run 'TestSchemaGoldenReports|TestWriteGitLabSAST|TestTemplateExamples' -update
go test ./internal/inventory -run TestWriteCycloneDX -update
git diff -- internal/output/testdata/ internal/inventory/testdata/
```

### Finding identity snapshots

`TestFindingIdentities` pins the report fingerprints, identifiers and baseline key fields of a fixed set of real rule findings in `internal/output/testdata/finding-identities.golden.json`. It runs with relative and absolute input paths, and loads the saved JSON and ignore-file keys through the baseline matcher. This catches message, job, path or fingerprint changes that would make existing findings appear new after an upgrade.

If the test fails, inspect the difference before updating anything. Keep its pipeline inputs and rule selection fixed: changing them to make the test pass would hide a compatibility change. For an intentional change, add an upgrade note to the PR description identifying affected report formats or baselines and any one-time resolved/new findings users should expect. Then update and review the snapshot:

```sh
go test ./internal/output -run '^TestFindingIdentities$' -update
git diff -- internal/output/testdata/finding-identities.golden.json
go test ./internal/output -run '^TestFindingIdentities$'
```

The golden file stores portable key fields rather than the baseline matcher's private in-memory keys; the matcher tests check the compatibility users depend on. No new public API is needed to expose those internals.

### Coverage

CI fails when statement coverage (`go test -cover`) drops below 92 % or branch coverage below 85 %. Branch coverage is measured with [gobco](https://github.com/rillig/gobco), one package at a time:

```sh
go install github.com/rillig/gobco@v1.3.4
gobco -branch ./rules
```

gobco lists every branch the tests never take. Both totals are on the summary page of each CI run.

### Fuzzing

glsec reads pipeline files other people wrote, so the parser, the rules and a whole scan have native Go fuzz targets. `go test ./...` replays their seed corpus (the fixtures) like ordinary tests. To fuzz one target:

```sh
go test ./internal/parser -run '^$' -fuzz '^FuzzParse$' -fuzztime 2m
go test ./rules           -run '^$' -fuzz '^FuzzRules$' -fuzztime 2m
go test ./cmd/glsec       -run '^$' -fuzz '^FuzzScan$'  -fuzztime 2m
```

The `Fuzz` workflow runs each target for 45 s on pull requests and pushes to `main`, and for 10 minutes every week. When a target fails, Go writes the input to `<package>/testdata/fuzz/<Target>/`, and CI uploads it as an artifact. Fix the bug and commit that file with the fix: it then replays on every `go test`.

## Linting

CI runs [golangci-lint](https://golangci-lint.run/) v2. To run it locally:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
golangci-lint run   # or: make lint
```

Enabled linters: `errcheck`, `govet`, `staticcheck`, `revive`, `gosec`, `misspell`, plus the `gofmt` formatter. The full config is in `.golangci.yml`.

## How to add a rule

Each rule lives in two files under `rules/`:

```text
rules/glNNN.go        # implementation
rules/glNNN_test.go   # tests
```

And one fixture under `testdata/fixtures/`:

```text
testdata/fixtures/glNNN-short-name.yml   # must be valid GitLab CI YAML
```

### Before you start — does an existing rule cover it?

Most ideas fit an existing rule. Another package manager, shell syntax or flag for a pattern glsec already reports goes into that rule's table or pattern, not into a new `GLNNN`: for example the install commands of GL023, the verification bypasses of GL069, or the PowerShell forms of GL004 and GL044. A new rule costs a doc page, a fixture, OWASP/CWE/ASVS mappings and its own false-positive surface; a table entry costs a line.

Add a new rule only when the case needs its own detection logic and threat model. If you are unsure, ask in the issue first.

### Step 1 — assign an ID

Once it is clear that a new rule is needed, pick the next available `GLNNN` number and open an issue describing what the rule detects and why it matters.

### Step 2 — create the rule file

```go
// rules/glNNN.go
package rules

import (
    "github.com/glsec/glsec/internal/finding"
    "github.com/glsec/glsec/internal/parser"
    "gopkg.in/yaml.v3"
)

type glNNN struct{}

var GLNNN = &glNNN{}

func (r *glNNN) ID() string { return "GLNNN" }

func (r *glNNN) Check(doc *yaml.Node, file string) []finding.Finding {
    var findings []finding.Finding
    mapping := parser.Unwrap(doc)

    // ... inspect the YAML tree and append findings ...

    return findings
}
```

Key helpers in `internal/parser`:

| Helper | What it does |
|--------|-------------|
| `parser.Unwrap(doc)` | Returns the top-level mapping node |
| `parser.FindKey(node, "key")` | Returns the value node for a key, or nil |
| `parser.FindKeyNode(node, "key")` | Returns both key and value nodes (use when you need the line number of the key itself) |
| `parser.EachJob(doc, fn)` | Calls fn for each job definition, skipping reserved top-level keys |

A rule that needs the `spec:` header of a component template implements `rule.SpecRule` (`CheckWithSpec`), and one that needs the whole parsed `Document` implements `rule.DocumentRule` (`CheckDocument`), both in `internal/rule`. `rules.Check(r, doc, file)` calls the right method, so tests of such a rule go through it.

Every `finding.Finding` needs `RuleID`, `Severity`, `Message`, `File`, `Line`, and `Job` when the finding belongs to a job: the corpus snapshots, the metamorphic test and the finding identities include it. Set `Col` when you have it.

Severities: `finding.Error` (must fix), `finding.Warn` (should fix), `finding.Info` (informational).

Shared helpers live in `rules/helpers.go` and `rules/shell.go` (and `runsInheritedJob` in `rules/gl017.go`). Check there before writing a new helper function. Most bugs fixed in 1.24.0 came from rules that skipped one of these:

**Jobs and inheritance.** GitLab merges keys from `extends:` and `default:` into a job, and never runs hidden jobs (names starting with `.`).

| Helper | What it does |
|--------|-------------|
| `NewInheritance(doc)` | Indexes the file once; build it at the start of `Check` |
| `in.Key(job, "key")` | The value of a key that applies to the job: its own, else from the jobs it extends in this file, else from `default:` |
| `in.Effective(job, "key")` / `in.Has(job, "key")` | The value with `extends:` deep-merged as GitLab does, for mappings such as `rules:` targets or `id_tokens:`; `Has` checks cheaply whether any template sets the key |
| `in.Chain(job, "key")` | The values of a key along the `extends:` chain, for keys GitLab deep-merges (`artifacts:`, `trigger:`) |
| `in.ExtendsResolved(job)` | Whether every template the job extends is in this file, so `Key` sees everything it inherits |
| `runsInheritedJob(in, name, job)` | Not a hidden template and `ExtendsResolved`: the usual guard for job-level rules that read inherited keys |
| `IsDeployLikeJob(jobName, job)` | Whether the job name, stage or `environment:` indicates deployment or release activity (the job's own keys only) |

**Scripts.** Read a script one command at a time, not as one block of text: a `|` inside quotes is not a pipe, and a word in a here-document is not a command.

| Helper | What it does |
|--------|-------------|
| `EachScriptBlock(doc, file, fn)` | Calls `fn` for every script sequence: global and `default:` sections, each job's scripts, hooks and `run:` steps. A sequence shared through a YAML anchor is visited once |
| `EachScriptBlockPerJob` / `EachScriptLinePerJob` | The same, visiting a shared sequence once per job, for rules whose result depends on the job; cache per-line work with `nodeMemo` |
| `EachScriptLine(doc, file, fn)` | Calls `fn` for every script line in the document |
| `CollectJobScriptLines(job)` | All scalar script lines of a single job |
| `shellCommands(item)` | Splits a script item into simple commands, respecting quotes, escapes, comments and here-documents |
| `commandWords(text)` / `commandName(words)` | The words of a command without keywords, assignments, `env` and quotes, and the base name of the program it runs |
| `logicalLines(item)` | The lines of an item, joining backslash continuations, with the index of the line each starts on |
| `parser.ScalarContentLine(item, i)` | The source line of the item's `i`-th line, so a finding inside a `\|` block points at the line that triggers it |

If you find that two or more rules need the same detection logic, extract it into `helpers.go` rather than duplicating it. Use unexported names for helpers that are only used within the `rules` package.

### Step 3 — register the rule

Add it to `rules/all.go`:

```go
func All() []rule.Rule {
    return []rule.Rule{
        GL001,
        // ...
        GLNNN,
    }
}
```

Then add its ID to the rule IDs the `.glsec.yml` schema lists, so editors accept `rules: {GL0NN: …}`:

```sh
go test ./cmd/glsec -run TestConfigSchema -update
```

A new config key goes into `schema/glsec.schema.json` by hand, with a description, and into `docs/glsec.example.yml`; `TestConfigSchema` and `TestConfigExampleLoads` fail until both have it.

### Step 4 — satisfy the consistency tests

`rules/consistency_test.go` and `rules/docexamples_test.go` run as part of `go test ./rules/` and check every rule returned by `All()`:

| Check | Requirement |
|-------|-------------|
| ID format | Matches `GL\d{3}` (e.g. `GL089`) and is not registered twice |
| Fixture | At least one `testdata/fixtures/glnnn-*.yml` (lowercase rule ID as prefix), and the fixtures produce at least one finding for the rule |
| OWASP | An entry in `rules/owasp.go`, and a `**OWASP:**` line in `docs/rules/GLNNN.md` naming the same categories |
| CWE | An entry in `rules/cwe.go`, with the CWE's name in `cweNames` |
| Rules overview | A `[GLNNN](rules/GLNNN.md)` link in `docs/rules.md`, under the `##` section of the rule's OWASP category |
| README | The "N rules across …" count equals the number of registered rules, and the rule's ID appears once, in the row of the README category table for its OWASP category |
| Doc sections | The rule doc has a `## Risk` or `## What glsec checks` section and a `## Safe alternative(s)` section; a doc with safe alternatives also has a YAML trigger example |
| Doc examples | Every YAML block under `## Trigger example(s)` in the rule doc produces a finding for the rule; every block under `## Safe alternative(s)` produces none, unless it contains `glsec:ignore GLNNN`. Each block must be a pipeline glsec accepts, without a script line YAML reads as a mapping (GL086) or a duplicate key (GL087) |

Steps 6 and 7 add the fixture, docs and README entries these checks look for.

### Step 5 — write unit tests

```go
// rules/glNNN_test.go
package rules

import (
    "testing"

    "github.com/glsec/glsec/internal/finding"
    "github.com/glsec/glsec/internal/parser"
)

func findingsNNN(t *testing.T, yaml string) []finding.Finding {
    t.Helper()
    doc, err := parser.Parse([]byte(yaml), "test.yml")
    if err != nil {
        t.Fatalf("parse error: %v", err)
    }
    return GLNNN.Check(doc.Root, "test.yml")
}

func TestGLNNN_Flagged(t *testing.T) {
    f := findingsNNN(t, `...`) // YAML that should trigger the rule
    if len(f) == 0 {
        t.Fatal("expected at least one finding")
    }
}

func TestGLNNN_Clean(t *testing.T) {
    f := findingsNNN(t, `...`) // YAML that should be clean
    if len(f) != 0 {
        t.Fatalf("expected no findings, got %v", f)
    }
}
```

Cover the happy path (flagged), the clean path, and any edge cases (empty values, missing keys, nested structures).

### Avoiding false positives

Before finishing a rule, work through this checklist:

**1. Verify the YAML key exists and does what you think**

Check the [GitLab CI/CD YAML syntax reference](https://docs.gitlab.com/ci/yaml/) to confirm the key you are inspecting is actually used by GitLab Runner, not just valid YAML syntax. A key that GitLab silently ignores cannot be a real vulnerability.

Common areas to check:

- [`artifacts:`](https://docs.gitlab.com/ci/yaml/#artifacts) — paths, exclude, reports, expire_in
- [`variables:`](https://docs.gitlab.com/ci/yaml/#variables) — job-level vs. global, `expand`/`value`/`description` sub-keys
- [`rules:`](https://docs.gitlab.com/ci/yaml/#rules) — if, changes, exists, when, variables
- [`trigger:`](https://docs.gitlab.com/ci/yaml/#trigger) — forward, strategy, branch

**2. Consider common legitimate patterns**

Before flagging a pattern, search for how it is used in real-world GitLab CI configs. If a pattern appears constantly in legitimate pipelines (e.g. `dist/$CI_COMMIT_REF_NAME` as an artifact path), the rule will create noise and get ignored or suppressed.

Ask: _is there a realistic, benign configuration that would trigger this finding?_ If yes, refine the detection or raise the threshold.

**3. Understand variable constraints**

[Predefined CI/CD variables](https://docs.gitlab.com/ci/variables/predefined_variables/) are not all equal. Variables derived from Git ref names (`CI_COMMIT_REF_NAME`, `CI_COMMIT_BRANCH`, `CI_COMMIT_TAG`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`) are constrained by [`git check-ref-format`](https://git-scm.com/docs/git-check-ref-format) and cannot contain sequences like `..`. Free-form text variables (`CI_COMMIT_MESSAGE`, `CI_MERGE_REQUEST_TITLE`, `CI_PIPELINE_NAME`, etc.) can contain arbitrary content. Treat them differently when assessing injection risk.

**4. Write an explicit no-finding test**

Every rule must have at least one test that asserts _zero_ findings for a realistic, valid config. Name it `TestGLNNN_<CommonPattern>NoFinding` or `TestGLNNN_Clean` so its intent is clear:

```go
func TestGLNNN_CommonPatternNoFinding(t *testing.T) {
    f := findingsNNN(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/$CI_COMMIT_REF_NAME   # common pattern — must not be flagged
    expire_in: 1 week
`)
    if len(f) != 0 {
        t.Fatalf("expected no findings for common artifact path, got %d", len(f))
    }
}
```

### Step 6 — add a fixture

Create `testdata/fixtures/glNNN-short-name.yml` with a realistic example that exercises the rule. The fixture must be valid GitLab CI YAML — CI validates all fixtures against the GitLab CI JSON schema via `check-jsonschema`. Only a rule that reports something the schema itself rejects may skip this: start its fixture with a `# schema: skip` comment that says why, and put `<!-- schema: skip … -->` before the trigger example in its docs file.

After the schema check, CI also sends every fixture and every trigger and safe example to GitLab's CI Lint API, which rejects things the schema can't see: a `stage:` missing from `stages:`, a `needs:` on a job that doesn't exist, a file without a visible job. So a fixture or example is a complete pipeline, not a fragment. Where GitLab can't accept a block by design (a placeholder include, a component template whose inputs have no values, invalid YAML the rule is about), add a `# lint: skip — reason` line to the fixture's header comment (after `# schema: skip` if it has both) or put `<!-- lint: skip — reason -->` before the block. This job needs a repository secret, so on a pull request from a fork it is skipped and the files are linted after the merge. Examples that use a recent GitLab feature should name the minimum version in the text, since the lint runs against the current gitlab.com release.

### Step 7 — add a docs file and update the overviews

Create `docs/rules/GLNNN.md` with the full rule documentation (see existing files for structure). Required sections:

- `# GLNNN — title`, then the `**Severity:**` and `**OWASP:**` lines (and `**CWE:**`, as in the newer docs)
- `## Risk` or `## What glsec checks`: why the pattern is dangerous and what exactly is reported
- `## Trigger example` (or `examples`): YAML the rule flags
- `## Safe alternative` (or `alternatives`): YAML it doesn't flag
- Notes on what is deliberately not reported, where it helps

`glsec explain` and the SARIF rule metadata (GitHub code scanning shows it as the rule's help) read the `Risk` / `What glsec checks` and `Safe alternative(s)` sections by name, so keep those headings exactly.

Then:

- add a row ``| [GLNNN](rules/GLNNN.md) | `warn` | one-line description |`` to the table of the rule's OWASP category in `docs/rules.md`
- add the rule ID to the matching row of the category table in `README.md` and raise the "N rules across …" count

## Developer Certificate of Origin

Every commit must be signed off. A sign-off is a line at the end of the commit message:

```text
Signed-off-by: Your Name <you@example.com>
```

With it you certify the [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the change or otherwise have the right to submit it under the project's license. `git commit -s` adds the line from your `user.name` and `user.email`; the name and email must match the commit's author.

A check on every pull request blocks commits without a sign-off. To fix them:

- the last commit: `git commit --amend -s --no-edit`, then force-push;
- several commits: `git rebase --signoff main`, then force-push;
- or, without rewriting history, add one empty commit that signs off the earlier ones, as the check's details page describes.

## License headers

Every source file starts with a copyright and license line, so the license stays with a file that is copied out of the repository on its own:

```go
// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0
```

Shell scripts, the `Dockerfile` and the `Makefile` use `#` instead of `//`; in a script the lines go right after the `#!` line. "The glsec Authors" are everyone who has contributed to glsec; the Git history records who wrote what. A CI check fails on any `.go` file, `Dockerfile`, `Makefile` or `bin/glsec` without the SPDX line.

All other files, such as Markdown, fixtures and images, get the same license from `REUSE.toml`, so the repository follows the [REUSE specification](https://reuse.software/). That rule assumes everything here was written for glsec: a file copied from another project keeps its own license and needs its own entry in `REUSE.toml`, with the license text in `LICENSES/`. `reuse lint` checks the whole repository.

## Code review

Every change to `main` goes through a pull request. Before it is merged, the reviewer checks the following. Today the reviewer is the maintainer ([GOVERNANCE.md](GOVERNANCE.md#roles)), who applies the same checks to their own pull requests.

- **Correctness.** The change does what the issue asks, and the tests cover it: a new rule has flagged, clean and edge-case tests and a fixture; a bug fix has a test that fails without the fix. CI is green, including the coverage floors.
- **False positives.** A new or changed rule has been run against real pipelines, and the pull request says how many findings it adds or removes (see [Avoiding false positives](#avoiding-false-positives)).
- **Security.** glsec reads untrusted pipeline files: input is never executed, paths stay inside the scanned repository, regular expressions are RE2, and error and log output does not print more of a file than a finding needs. [ARCHITECTURE.md](ARCHITECTURE.md) has the threat model; a change that touches one of its boundaries says so in the pull request.
- **Dependencies.** A new or updated dependency meets the [dependency rules](#dependencies).
- **Docs.** User-visible behaviour is documented in the same pull request: [Using glsec](docs/usage.md) or the other pages in `docs/`, `docs/rules/GLNNN.md`, and the rule table in the README.
- **Conventions.** Branch name, signed-off commits and a pull request description that says what changed, why, and how to test it.

The reviewer leaves comments on anything that needs to change; a pull request is merged only when none are open.

## Commit and PR conventions

- **Commit messages:** one short line (`feat: add GL090 rule`, `fix: GL002 false positive on quoted vars`), signed off with `-s` (see above). No other body, no `Co-Authored-By` trailers.
- **Branch names:** `<type>/issue-<N>-<slug>` — e.g. `feat/issue-13-gl090-rule`; for a change without an issue, `<type>/<slug>`.
- **PR descriptions:** write the context here — what the rule detects, why it matters, how to test it, any edge cases considered.
- One branch per issue; one PR per branch.
- **Tests:** new functionality and bug fixes come with tests in the same PR. A new rule needs its fixture and unit tests (see above); a bug fix needs a test that fails without the fix. CI (tests on Linux, macOS and Windows, lint, fuzzing, CodeQL) must pass before merging.

## AI-assisted contributions

You're welcome to use AI tools. What counts is the change itself and that you stand behind it:

- Say in the pull request that you used one and what it did. The template has a field for it.
- Read and understand every line before you open the pull request, and be ready to explain a change and answer review questions yourself.
- Check what the tool tells you about GitLab. Job names, keyword behaviour and template defaults are easy to get wrong; link the documentation or template you checked against.
- Run the checks described here locally where you can, and say which ones you couldn't run.
- Keep a pull request to one issue. Pull requests that look generated in bulk, with many unrelated changes or a description that doesn't match the code, will be closed.

The sign-off works the same way: with it you certify that you have the right to submit the change, however it was written.

## Fixture validation

Fixtures, the rule doc examples and the example `.glsec.yml` are validated in CI with:

```sh
pip install --require-hashes --no-deps -r .github/requirements/check-jsonschema.txt
mapfile -t fixtures < <(grep -L '^# schema: skip' testdata/fixtures/*.yml)
check-jsonschema --builtin-schema gitlab-ci "${fixtures[@]}"
python3 .github/scripts/doc-examples.py /tmp/doc-examples
check-jsonschema --builtin-schema gitlab-ci /tmp/doc-examples/*.yml
check-jsonschema --schemafile schema/glsec.schema.json docs/glsec.example.yml
```

Run this locally before pushing if you add or change a fixture, a rule doc or the config. The report golden files are validated in the same job; see [Report schemas](#report-schemas).

The GitLab lint runs with a token for a gitlab.com project (`GITLAB_LINT_TOKEN`, `GITLAB_LINT_PROJECT`) that may only validate CI configuration. With your own token and project:

```sh
python3 .github/scripts/doc-examples.py /tmp/doc-examples lint
GITLAB_LINT_TOKEN=... GITLAB_LINT_PROJECT=<id> \
  python3 .github/scripts/gitlab-ci-lint.py lint /tmp/gitlab-lint-cache \
  $(grep -L '^# lint: skip' testdata/fixtures/*.yml) /tmp/doc-examples/*.yml
```

Passing files are cached per GitLab major.minor version, so a second run only sends what changed.

Before a release, `ci-lint-diff.py` checks the parser against real pipelines (#895). It sends a set of `.gitlab-ci.yml` files to the same lint API and through glsec and counts the files GitLab accepts but glsec can't scan (exit 2); each of those is a parser bug:

```sh
go build -o /tmp/glsec ./cmd/glsec
GITLAB_LINT_TOKEN=... GITLAB_LINT_PROJECT=<id> \
  python3 .github/scripts/ci-lint-diff.py /tmp/glsec /tmp/ci-lint-diff pipelines/*.yml
```

It also compares the jobs: for files both accept, the jobs GitLab's lint API lists against `glsec inventory --format jobs` (#930). A job only glsec scans, or one only GitLab creates in a file without `include:`, puts the file in the group "both accept, jobs differ". `/tmp/ci-lint-diff/results.jsonl` lists the group, glsec's exit code and error, GitLab's errors and the job difference for every file. The GitLab answers are cached by content, so a rerun only sends new files.

## Regression corpus

`testdata/corpus/` holds short pipelines taken from past false-positive and false-negative issues, each with a `.golden` snapshot of its findings (`LINE RULE SEVERITY JOB`). `TestCorpus` fails when a finding appears or disappears. When you fix a false positive or a missed finding, add the case: a small `.yml` with a comment that names the issue and what should or shouldn't be reported, then

```sh
go test ./cmd/glsec -run TestCorpus -update
```

and review the snapshot diff before committing it. Cases for issues that are still open record today's behaviour and say so in their comment; the snapshot changes with the fix.

## Metamorphic test

`TestMetamorphic` rewrites every pipeline in `testdata/fixtures` and `testdata/corpus` into forms that mean the same to GitLab (CRLF, flow style, other quoting, `script:` as a string or a list, jobs reversed, anchors expanded, keys moved into a template the job `extends:` or merges with `<<:`) and fails when the findings change; lines may move. A difference is either a rule that matches on spelling instead of meaning, or a rewrite that isn't equivalent for that rule. The second kind, and rule gaps that have an issue, go into `knownDifferences` as `transform/rule` with the reason. The test also fails on an entry that no longer matches, so remove it when you fix the rule.

```sh
go test ./cmd/glsec -run TestMetamorphic
```

## Performance

`TestRulesScaleLinearly` runs every rule on a large generated pipeline and on one four times its size, and fails when a rule takes more than ten times as long, which means it grows faster than linearly. It skips itself under `-race`, which makes it take minutes; CI runs it once without. To compare a change locally:

```sh
go test ./cmd/glsec -run '^$' -bench . -count 10 > old.txt   # on main
go test ./cmd/glsec -run '^$' -bench . -count 10 > new.txt   # on your branch
benchstat old.txt new.txt
```

`BenchmarkParse`, `BenchmarkRules` and `BenchmarkRun` use a pipeline of 2,000 jobs with `extends:` and `!reference` chains, anchors, long script blocks and a very long line.
