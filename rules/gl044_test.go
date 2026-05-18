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
