package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings021(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL021.Check(doc.Root, "test.yml")
}

func TestGL021_EchoToken(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $MY_API_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL021_EchoPassword(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $DEPLOY_PASSWORD
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for PASSWORD variable, got %d", len(f))
	}
}

func TestGL021_EchoCIJobToken(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $CI_JOB_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_JOB_TOKEN, got %d", len(f))
	}
}

func TestGL021_PrintfSecret(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - printf "%s\n" "$API_SECRET"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for printf with secret, got %d", len(f))
	}
}

func TestGL021_EchoKey(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $AWS_SECRET_ACCESS_KEY
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for _KEY variable, got %d", len(f))
	}
}

func TestGL021_SafePresenceCheck_NoFinding(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - '[ -n "$MY_API_TOKEN" ] && echo "token set"'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for presence check, got %d", len(f))
	}
}

func TestGL021_NoSecretVar_NoFinding(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo "Branch is $CI_COMMIT_REF_NAME"
    - echo "Job ID: $CI_JOB_ID"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-secret variables, got %d", len(f))
	}
}

func TestGL021_NoPrintCommand_NoFinding(t *testing.T) {
	f := findings021(t, `
deploy:
  script:
    - curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/deploy
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when no print command present, got %d", len(f))
	}
}

func TestGL021_BraceExpansion(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo ${DEPLOY_PASSWORD}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace expansion, got %d", len(f))
	}
}

func TestGL021_BeforeScript(t *testing.T) {
	f := findings021(t, `
debug:
  before_script:
    - echo $CI_REGISTRY_PASSWORD
  script:
    - docker login
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL021_MultipleFindings(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $API_TOKEN
    - echo $DEPLOY_PASSWORD
    - echo "non-secret info"
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL021_LineNumber(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $MY_API_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
