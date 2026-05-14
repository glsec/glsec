package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings010(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL010.Check(doc.Root, "test.yml")
}

func TestGL010_ForwardPipelineVariables(t *testing.T) {
	f := findings010(t, `
trigger-downstream:
  trigger:
    project: org/downstream
    forward:
      pipeline_variables: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL010_ForwardFalse_NoFinding(t *testing.T) {
	f := findings010(t, `
trigger-downstream:
  trigger:
    project: org/downstream
    forward:
      pipeline_variables: false
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when pipeline_variables: false, got %d", len(f))
	}
}

func TestGL010_NoForward_NoFinding(t *testing.T) {
	f := findings010(t, `
trigger-downstream:
  trigger:
    project: org/downstream
`)
	if len(f) != 0 {
		t.Errorf("expected no finding without forward:, got %d", len(f))
	}
}

func TestGL010_ScalarTrigger_NoFinding(t *testing.T) {
	// Simple trigger form — no forward: key possible
	f := findings010(t, `
trigger-downstream:
  trigger: org/downstream
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for scalar trigger, got %d", len(f))
	}
}

func TestGL010_YamlVariablesOnly_NoFinding(t *testing.T) {
	// Forwarding yaml_variables (YAML-defined vars) is less risky than pipeline_variables
	f := findings010(t, `
trigger-downstream:
  trigger:
    project: org/downstream
    forward:
      yaml_variables: true
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for yaml_variables only, got %d", len(f))
	}
}

func TestGL010_MultipleJobs(t *testing.T) {
	f := findings010(t, `
trigger-a:
  trigger:
    project: org/a
    forward:
      pipeline_variables: true

trigger-b:
  trigger:
    project: org/b
    forward:
      pipeline_variables: true

build:
  script: [make]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL010_LineNumber(t *testing.T) {
	f := findings010(t, `
trigger-downstream:
  trigger:
    project: org/downstream
    forward:
      pipeline_variables: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
