package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings053(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL053.Check(doc.Root, "test.yml")
}

func TestGL053_NoWorkflowBlock(t *testing.T) {
	f := findings053(t, `
build:
  script: make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing workflow, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %q", f[0].Severity)
	}
	if f[0].RuleID != "GL053" {
		t.Errorf("expected GL053, got %q", f[0].RuleID)
	}
}

func TestGL053_WorkflowWithoutRules(t *testing.T) {
	f := findings053(t, `
workflow:
  name: 'Pipeline for $CI_COMMIT_BRANCH'

build:
  script: make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for workflow without rules, got %d", len(f))
	}
}

func TestGL053_RulesWithoutSourceGate(t *testing.T) {
	f := findings053(t, `
workflow:
  rules:
    - when: always

build:
  script: make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unrestricted rules, got %d", len(f))
	}
}

func TestGL053_GatedOnPipelineSource(t *testing.T) {
	f := findings053(t, `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_COMMIT_TAG

build:
  script: make
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for source-gated workflow, got %d", len(f))
	}
}

func TestGL053_GatedOnBranch(t *testing.T) {
	f := findings053(t, `
workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

build:
  script: make
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when gated on branch, got %d", len(f))
	}
}

func TestGL053_GatedOnMergeRequestIID(t *testing.T) {
	f := findings053(t, `
workflow:
  rules:
    - if: $CI_MERGE_REQUEST_IID

build:
  script: make
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when gated on MR IID, got %d", len(f))
	}
}

func TestGL053_MixedRulesWithOneSourceGate(t *testing.T) {
	f := findings053(t, `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"
    - when: always

build:
  script: make
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when at least one rule gates on source, got %d", len(f))
	}
}
