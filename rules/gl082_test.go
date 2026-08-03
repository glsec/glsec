package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings082(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL082.Check(doc.Root, "test.yml")
}

func TestGL082_TopLevelDisabled_Warn(t *testing.T) {
	f := findings082(t, `
variables:
  SAST_DISABLED: "true"
build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "SAST") {
		t.Errorf("message should name the scan, got %q", f[0].Message)
	}
}

func TestGL082_AllDisableVars(t *testing.T) {
	for v := range scanDisableVars {
		f := findings082(t, "variables:\n  "+v+": \"true\"\nbuild:\n  script: [make]\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %s, got %d", v, len(f))
		}
	}
}

func TestGL082_DastDefaultBranchVar_Warn(t *testing.T) {
	f := findings082(t, `
variables:
  DAST_DISABLED_FOR_DEFAULT_BRANCH: "true"
build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "default branch") {
		t.Errorf("expected the default-branch wording, got %q", f[0].Message)
	}
}

func TestGL082_ValueOne_Warn(t *testing.T) {
	f := findings082(t, `
variables:
  SECRET_DETECTION_DISABLED: "1"
build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf(`expected 1 finding for "1", got %d`, len(f))
	}
}

// An unquoted YAML boolean is stringified to "true" by GitLab, so every
// boolean spelling satisfies the template gate.
func TestGL082_YAMLBooleanSpellings_Warn(t *testing.T) {
	for _, v := range []string{"true", "True", "TRUE"} {
		f := findings082(t, "variables:\n  SAST_DISABLED: "+v+"\nbuild:\n  script: [make]\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for unquoted %s, got %d", v, len(f))
		}
	}
}

// The templates compare `$VAR == 'true'` against a string, case-sensitively, so
// a quoted "True" leaves the scan running and must not be reported as disabled.
func TestGL082_QuotedTrueMixedCase_NoFinding(t *testing.T) {
	for _, v := range []string{`"True"`, `"TRUE"`, `"yes"`, `"on"`} {
		f := findings082(t, "variables:\n  SAST_DISABLED: "+v+"\nbuild:\n  script: [make]\n")
		if len(f) != 0 {
			t.Errorf("expected no finding for %s, got %d", v, len(f))
		}
	}
}

func TestGL082_FalseValues_NoFinding(t *testing.T) {
	for _, v := range []string{`"false"`, "false", `"0"`, "0", `""`} {
		f := findings082(t, "variables:\n  SAST_DISABLED: "+v+"\nbuild:\n  script: [make]\n")
		if len(f) != 0 {
			t.Errorf("expected no finding for %s, got %d", v, len(f))
		}
	}
}

func TestGL082_UnrelatedVariable_NoFinding(t *testing.T) {
	f := findings082(t, `
variables:
  DEPLOY_DISABLED: "true"
  SAST_EXCLUDED_PATHS: "spec, test"
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding, got %d", len(f))
	}
}

func TestGL082_DefaultVariables_Warn(t *testing.T) {
	f := findings082(t, `
default:
  variables:
    CONTAINER_SCANNING_DISABLED: "true"
build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for default: variables:, got %d", len(f))
	}
}

func TestGL082_JobVariables_WarnWithJobName(t *testing.T) {
	f := findings082(t, `
build:
  variables:
    DEPENDENCY_SCANNING_DISABLED: "true"
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for job variables, got %d", len(f))
	}
	if f[0].Job != "build" {
		t.Errorf("expected job attribution %q, got %q", "build", f[0].Job)
	}
}

// The extended variable form carries the value under `value:`.
func TestGL082_ExtendedVariableForm_Warn(t *testing.T) {
	f := findings082(t, `
variables:
  SAST_DISABLED:
    value: "true"
    description: "turn SAST off"
build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for the extended form, got %d", len(f))
	}
}

func TestGL082_MultipleDisabled_OnePerVariable(t *testing.T) {
	f := findings082(t, `
variables:
  SAST_DISABLED: "true"
  SECRET_DETECTION_DISABLED: "true"
  DAST_DISABLED: "1"
build:
  script: [make]
`)
	if len(f) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(f))
	}
}

func TestGL082_CleanPipeline_NoFinding(t *testing.T) {
	f := findings082(t, `
include:
  - template: Jobs/SAST.gitlab-ci.yml
variables:
  SAST_EXCLUDED_PATHS: "spec, test, tests, tmp"
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding, got %d", len(f))
	}
}

func TestGL082_LineNumber(t *testing.T) {
	f := findings082(t, `
variables:
  SAST_DISABLED: "true"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
