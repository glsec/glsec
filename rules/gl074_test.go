package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings074rule(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL074.Check(doc.Root, "test.yml")
}

func TestGL074_OrTrue(t *testing.T) {
	f := findings074rule(t, `
deploy:
  rules:
    - if: '$CI_COMMIT_BRANCH || true'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for '|| true', got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL074_LeadingTrue(t *testing.T) {
	f := findings074rule(t, `
deploy:
  rules:
    - if: 'true || $CI_COMMIT_BRANCH'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 'true ||', got %d", len(f))
	}
}

func TestGL074_ConstEqual(t *testing.T) {
	f := findings074rule(t, `
deploy:
  rules:
    - if: '"true" == "true"'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for constant ==, got %d", len(f))
	}
}

func TestGL074_ConstNotEqualDifferent(t *testing.T) {
	f := findings074rule(t, `
deploy:
  rules:
    - if: '"a" != "b"'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for constant != different literals, got %d", len(f))
	}
}

func TestGL074_VarEqAndNeqSameLiteral(t *testing.T) {
	f := findings074rule(t, `
deploy:
  rules:
    - if: '$CI_PIPELINE_SOURCE != "schedule" || $CI_PIPELINE_SOURCE == "schedule"'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for A || !A tautology, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "CI_PIPELINE_SOURCE") {
		t.Errorf("expected variable in message, got %q", f[0].Message)
	}
}

func TestGL074_WorkflowRules(t *testing.T) {
	f := findings074rule(t, `
workflow:
  rules:
    - if: '$CI_COMMIT_BRANCH || true'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in workflow:rules, got %d", len(f))
	}
}

func TestGL074_JobNameSet(t *testing.T) {
	f := findings074rule(t, `
my_deploy:
  rules:
    - if: '$X || true'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Job != "my_deploy" {
		t.Errorf("expected Job=my_deploy, got %q", f[0].Job)
	}
}

// --- negative cases (must NOT fire) ---

func TestGL074_NormalCondition_NoFinding(t *testing.T) {
	f := findings074rule(t, `
deploy:
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
`)
	if len(f) != 0 {
		t.Errorf("normal conditions — expected no finding, got %d", len(f))
	}
}

func TestGL074_OrOfTwoVars_NoFinding(t *testing.T) {
	f := findings074rule(t, `
deploy:
  rules:
    - if: '$CI_COMMIT_TAG || $CI_COMMIT_BRANCH'
`)
	if len(f) != 0 {
		t.Errorf("OR of two vars is not always true — expected no finding, got %d", len(f))
	}
}

func TestGL074_TrueNarrowedByAnd_NoFinding(t *testing.T) {
	// $X || (true && $Y) == $X || $Y — not always true.
	f := findings074rule(t, `
deploy:
  rules:
    - if: '$X || true && $CI_COMMIT_BRANCH'
`)
	if len(f) != 0 {
		t.Errorf("true narrowed by && is not always true — expected no finding, got %d", len(f))
	}
}

func TestGL074_DifferentLiterals_NoFinding(t *testing.T) {
	// $V == "a" || $V != "b" — false when V == "b"; not always true.
	f := findings074rule(t, `
deploy:
  rules:
    - if: '$CI_COMMIT_BRANCH == "a" || $CI_COMMIT_BRANCH != "b"'
`)
	if len(f) != 0 {
		t.Errorf("different literals — expected no finding, got %d", len(f))
	}
}

func TestGL074_StringEqVar_NoFinding(t *testing.T) {
	f := findings074rule(t, `
deploy:
  rules:
    - if: '$CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH'
`)
	if len(f) != 0 {
		t.Errorf("var == var — expected no finding, got %d", len(f))
	}
}

func TestGL074_NoRules_NoFinding(t *testing.T) {
	f := findings074rule(t, `
deploy:
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("no rules — expected no finding, got %d", len(f))
	}
}
