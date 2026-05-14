package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings018(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL018.Check(doc.Root, "test.yml")
}

func TestGL018_PipelineLevelToken(t *testing.T) {
	f := findings018(t, `
variables:
  PROD_API_TOKEN: $PROD_API_TOKEN

build:
  script: go build
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL018_PipelineLevelPassword(t *testing.T) {
	f := findings018(t, `
variables:
  PROD_DB_PASSWORD: $PROD_DB_PASSWORD
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for _PASSWORD, got %d", len(f))
	}
}

func TestGL018_PipelineLevelKey(t *testing.T) {
	f := findings018(t, `
variables:
  AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for _KEY suffix, got %d", len(f))
	}
}

func TestGL018_BraceExpansionValue(t *testing.T) {
	f := findings018(t, `
variables:
  API_TOKEN: ${CI_API_TOKEN}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace-expansion value, got %d", len(f))
	}
}

func TestGL018_ExtendedForm(t *testing.T) {
	f := findings018(t, `
variables:
  DEPLOY_TOKEN:
    value: $DEPLOY_TOKEN
    description: "Deployment token"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for extended variable form, got %d", len(f))
	}
}

func TestGL018_LiteralValue_NoFinding(t *testing.T) {
	// Literal values are GL006's territory
	f := findings018(t, `
variables:
  API_TOKEN: some-non-secret-value
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-variable-reference value, got %d", len(f))
	}
}

func TestGL018_NonSecretName_NoFinding(t *testing.T) {
	f := findings018(t, `
variables:
  REGISTRY_URL: $CI_REGISTRY
  NODE_ENV: production
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-secret variable names, got %d", len(f))
	}
}

func TestGL018_JobLevelOnly_NoFinding(t *testing.T) {
	// Job-level variables are appropriately scoped — not flagged
	f := findings018(t, `
deploy:
  variables:
    DEPLOY_TOKEN: $DEPLOY_TOKEN
  script: ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for job-level variables, got %d", len(f))
	}
}

func TestGL018_MultipleSecrets(t *testing.T) {
	f := findings018(t, `
variables:
  PROD_DB_PASSWORD: $PROD_DB_PASSWORD
  API_TOKEN: $MY_API_TOKEN
  REGISTRY_URL: $CI_REGISTRY
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (password + token), got %d", len(f))
	}
}

func TestGL018_LineNumber(t *testing.T) {
	f := findings018(t, `
variables:
  API_TOKEN: $MY_API_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
