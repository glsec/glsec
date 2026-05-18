package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings043(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL043.Check(doc.Root, "test.yml")
}

func TestGL043_PrefixMatchBranch(t *testing.T) {
	f := findings043(t, `
deploy-prod:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^release/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for prefix match, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL043_NoAnchorsBranch(t *testing.T) {
	f := findings043(t, `
deploy-prod:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH =~ /release/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unanchored match, got %d", len(f))
	}
}

func TestGL043_FullyAnchoredNoFinding(t *testing.T) {
	f := findings043(t, `
deploy-prod:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^release$/
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for fully anchored pattern, got %d", len(f))
	}
}

func TestGL043_UserLoginPrefixMatch(t *testing.T) {
	f := findings043(t, `
privileged-job:
  script: [./admin.sh]
  rules:
    - if: $GITLAB_USER_LOGIN =~ /^admin/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for user login prefix match, got %d", len(f))
	}
}

func TestGL043_UserLoginFullyAnchoredNoFinding(t *testing.T) {
	f := findings043(t, `
privileged-job:
  script: [./admin.sh]
  rules:
    - if: $GITLAB_USER_LOGIN =~ /^admin$/
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for fully anchored user login, got %d", len(f))
	}
}

func TestGL043_NamespacePrefixMatch(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_PROJECT_NAMESPACE =~ /^myteam/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for namespace prefix match, got %d", len(f))
	}
}

func TestGL043_RefNamePrefixMatch(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_REF_NAME =~ /^v/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ref name prefix match, got %d", len(f))
	}
}

func TestGL043_WorkflowRules(t *testing.T) {
	f := findings043(t, `
workflow:
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^release/

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in workflow rules, got %d", len(f))
	}
}

func TestGL043_EqualityNoFinding(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for == operator, got %d", len(f))
	}
}

func TestGL043_UnrelatedVariableNoFinding(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_PIPELINE_SOURCE =~ /^push/
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for non-target variable, got %d", len(f))
	}
}

func TestGL043_MultipleConditionsOneUnanchored(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^main$/ && $GITLAB_USER_LOGIN =~ /^admin/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (only the unanchored pattern), got %d", len(f))
	}
}

func TestGL043_NoRulesNoFinding(t *testing.T) {
	f := findings043(t, `
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when no rules block, got %d", len(f))
	}
}
