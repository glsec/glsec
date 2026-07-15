# Contributing to glsec

## Dev environment

**Requirements:** Go 1.25+

```sh
git clone https://github.com/glsec/glsec.git
cd glsec
go build ./...
go test ./...
```

No code generation, no build scripts — `go build` is all you need.

## Running tests

```sh
go test ./...                   # all packages
go test -race ./...             # with race detector (what CI runs)
go test ./rules/... -v -run GL001  # single rule
```

## Linting

CI runs [golangci-lint](https://golangci-lint.run/) v2. To run it locally:

```sh
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
golangci-lint run
```

Enabled linters: `errcheck`, `govet`, `staticcheck`, `revive`, `gosec`, `misspell`. The full config is in `.golangci.yml`.

## How to add a rule

Each rule lives in two files under `rules/`:

```
rules/glNNN.go        # implementation
rules/glNNN_test.go   # tests
```

And one fixture under `testdata/fixtures/`:

```
testdata/fixtures/glNNN-short-name.yml   # must be valid GitLab CI YAML
```

### Step 1 — assign an ID

Pick the next available `GLNNN` number and open an issue describing what the rule detects and why it matters.

### Step 2 — create the rule file

```go
// rules/gl006.go
package rules

import (
    "github.com/glsec/glsec/internal/finding"
    "github.com/glsec/glsec/internal/parser"
    "gopkg.in/yaml.v3"
)

type gl006 struct{}

var GL006 = &gl006{}

func (r *gl006) ID() string { return "GL006" }

func (r *gl006) Check(doc *yaml.Node, file string) []finding.Finding {
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

Every `finding.Finding` needs `RuleID`, `Severity`, `Message`, `File`, `Line`. Set `Col` when you have it.

Severities: `finding.Error` (must fix), `finding.Warn` (should fix), `finding.Info` (informational).

Shared helpers live in `rules/helpers.go`. Check there before writing a new helper function:

| Helper | What it does |
|--------|-------------|
| `CollectJobScriptLines(job)` | Returns all scalar script lines across `before_script`, `script`, `after_script` for a single job |
| `EachScriptLine(doc, file, fn)` | Calls `fn` for every script line in the whole document — global sections, `default:`, and all jobs. Use this for rules that scan script content across the entire file |
| `IsDeployLikeJob(jobName, job)` | Returns true when the job name, stage, or `environment:` key indicates deployment or release activity |

If you find that two or more rules need the same detection logic, extract it into `helpers.go` rather than duplicating it. Use unexported names for helpers that are only used within the `rules` package.

### Step 3 — register the rule

Add it to `rules/all.go`:

```go
func All() []rule.Rule {
    return []rule.Rule{GL001, GL002, GL003, GL004, GL005, GL006}
}
```

### Step 4 — satisfy the consistency test

`rules/consistency_test.go` runs automatically as part of `go test ./rules/` and enforces three invariants for every rule returned by `All()`:

| Check | Requirement |
|-------|-------------|
| ID format | Must match `GL\d{3}` (e.g. `GL006`) |
| Docs file | `docs/rules/GLNNN.md` must exist and contain at least one `CICD-SEC-N` or `OWASP` reference |
| Fixture | At least one `testdata/fixtures/glnnn-*.yml` file must exist (lowercase rule ID as prefix) |

All three must be in place before the test suite passes.

### Step 5 — write unit tests

```go
// rules/gl006_test.go
package rules

import (
    "testing"
    "github.com/glsec/glsec/internal/parser"
)

func checkGL006(t *testing.T, src []byte) []finding.Finding {
    t.Helper()
    doc, err := parser.Parse(src, "test.yml")
    if err != nil {
        t.Fatalf("parse error: %v", err)
    }
    return GL006.Check(doc.Root, "test.yml")
}

func TestGL006_Flagged(t *testing.T) {
    src := []byte(`...`)  // YAML that should trigger the rule
    findings := checkGL006(t, src)
    if len(findings) == 0 {
        t.Fatal("expected at least one finding")
    }
}

func TestGL006_Clean(t *testing.T) {
    src := []byte(`...`)  // YAML that should be clean
    findings := checkGL006(t, src)
    if len(findings) != 0 {
        t.Fatalf("expected no findings, got %v", findings)
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
func TestGL006_CommonPatternNoFinding(t *testing.T) {
    f := findings006(t, `
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

Create `testdata/fixtures/glNNN-short-name.yml` with a realistic example that exercises the rule. The fixture must be valid GitLab CI YAML — CI validates all fixtures against the GitLab CI JSON schema via `check-jsonschema`.

### Step 7 — update the README and add a docs file

Create `docs/rules/GLNNN.md` with the full rule documentation (see existing files for structure). Required sections:

- Rule ID, severity, OWASP reference (`CICD-SEC-N`), zizmor analogue if applicable
- Risk explanation
- Trigger example (flagged YAML)
- Safe alternative
- Detection notes

Add a row to the rules summary table in `README.md` linking to the new docs file.

## Commit and PR conventions

- **Commit messages:** one short line (`feat: add GL006 rule`, `fix: GL002 false positive on quoted vars`). No body, no `Co-Authored-By` trailers.
- **Branch names:** `<type>/issue-<N>-<slug>` — e.g. `feat/issue-13-gl006-rule`.
- **PR descriptions:** write the context here — what the rule detects, why it matters, how to test it, any edge cases considered.
- One branch per issue; one PR per branch.

## Fixture validation

Fixtures are validated in CI with:

```sh
pip install check-jsonschema
check-jsonschema --builtin-schema gitlab-ci testdata/fixtures/*.yml
```

Run this locally before pushing if you add or change a fixture.
