// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings044(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL044.Check(doc.Root, "test.yml")
}

func TestGL044_MRTriggerWithSHACheckout(t *testing.T) {
	f := findings044(t, `
security-scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
    - ./scan.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL044_OnlyMergeRequestsWithSHACheckout(t *testing.T) {
	f := findings044(t, `
scan:
  only:
    - merge_requests
  script:
    - git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding via only: syntax, got %d", len(f))
	}
}

func TestGL044_SHAInBeforeScript(t *testing.T) {
	f := findings044(t, `
scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  before_script:
    - git fetch origin $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
    - git checkout FETCH_HEAD
  script:
    - ./analyze.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for SHA in before_script, got %d", len(f))
	}
}

func TestGL044_SHAInImage(t *testing.T) {
	f := findings044(t, `
scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  image: myregistry/myapp:$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
  script:
    - ./scan.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for SHA in image, got %d", len(f))
	}
}

func TestGL044_NoMRTriggerNoFinding(t *testing.T) {
	f := findings044(t, `
scan:
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  script:
    - git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without MR trigger, got %d", len(f))
	}
}

func TestGL044_MRTriggerNoSHANoFinding(t *testing.T) {
	f := findings044(t, `
test:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - npm test
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without SHA reference, got %d", len(f))
	}
}

func TestGL044_MRTriggerBranchNameNoFinding(t *testing.T) {
	f := findings044(t, `
test:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - echo "Branch is $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for branch name only (not SHA), got %d", len(f))
	}
}

func TestGL044_NoRulesNoFinding(t *testing.T) {
	f := findings044(t, `
build:
  script:
    - make build
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for job with no rules, got %d", len(f))
	}
}

func TestGL044_JobNameInFinding(t *testing.T) {
	f := findings044(t, `
security-scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Job != "security-scan" {
		t.Errorf("expected job name 'security-scan', got %q", f[0].Job)
	}
}

func TestGL044_PowerShellEnvForm(t *testing.T) {
	f := findings044(t, `
test:
  tags: [windows]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git fetch origin $env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
    - git checkout $env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
`)
	if len(f) != 1 || f[0].Line != 8 {
		t.Fatalf("expected 1 finding on the checkout for PowerShell $env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA, got %d: %v", len(f), f)
	}
}

func TestGL044_PowerShellBraceEnvForm(t *testing.T) {
	f := findings044(t, `
test:
  tags: [windows]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git checkout ${env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for PowerShell ${env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA}, got %d: %v", len(f), f)
	}
}

func TestGL044_PowerShellMixedCaseEnvForm(t *testing.T) {
	f := findings044(t, `
test:
  tags: [windows]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git checkout $Env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mixed case $Env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA, got %d: %v", len(f), f)
	}
}

func TestGL044_PosixLowercaseNoFinding(t *testing.T) {
	f := findings044(t, `
test:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git checkout $ci_merge_request_source_branch_sha
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for lowercase POSIX $ci_merge_request_source_branch_sha, got %d: %v", len(f), f)
	}
}

func TestGL044_CurlyBraceSyntax(t *testing.T) {
	f := findings044(t, `
scan:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - git checkout ${CI_MERGE_REQUEST_SOURCE_BRANCH_SHA}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ${VAR} syntax, got %d", len(f))
	}
}

// Reading history with the SHA checks out nothing (#980).
func TestGL044_HistoryOnly(t *testing.T) {
	for _, line := range []string{
		`git log "$CI_MERGE_REQUEST_DIFF_BASE_SHA..$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"`,
		`git rev-list --count $CI_MERGE_REQUEST_TARGET_BRANCH_SHA..$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA`,
		`commitlint --from "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --to "$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"`,
		`git diff --name-only $CI_MERGE_REQUEST_DIFF_BASE_SHA $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA`,
		`git fetch origin $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA`,
		`echo "testing ${CI_MERGE_REQUEST_SOURCE_BRANCH_SHA:-$CI_COMMIT_SHA}"`,
	} {
		f := findings044(t, "lint:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n  script:\n    - '"+line+"'\n")
		if len(f) != 0 {
			t.Errorf("%s: got %v, want no finding", line, f)
		}
	}
	for _, line := range []string{
		`git checkout "$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"`,
		`git -C src switch --detach $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA`,
		`git reset --hard ${CI_MERGE_REQUEST_SOURCE_BRANCH_SHA}`,
		`git worktree add ../mr $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA`,
	} {
		f := findings044(t, "lint:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n  script:\n    - '"+line+"'\n")
		if len(f) != 1 {
			t.Errorf("%s: got %v, want one finding", line, f)
		}
	}
}
