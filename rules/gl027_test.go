package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings027(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL027.Check(doc.Root, "test.yml")
}

func TestGL027_MissingMasked(t *testing.T) {
	f := findings027(t, `
variables:
  DEPLOY_TOKEN:
    value: "glpat-xxxx"
    description: "deploy token"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL027_MaskedFalse(t *testing.T) {
	f := findings027(t, `
variables:
  DEPLOY_TOKEN:
    value: "glpat-xxxx"
    masked: false
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for masked: false, got %d", len(f))
	}
}

func TestGL027_MaskedTrue_NoFinding(t *testing.T) {
	f := findings027(t, `
variables:
  DEPLOY_TOKEN:
    value: "glpat-xxxx"
    masked: true
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when masked: true, got %d", len(f))
	}
}

func TestGL027_ScalarForm_NoFinding(t *testing.T) {
	f := findings027(t, `
variables:
  DEPLOY_TOKEN: "glpat-xxxx"
`)
	if len(f) != 0 {
		t.Errorf("scalar form cannot carry masked: true — expected no finding, got %d", len(f))
	}
}

func TestGL027_NonSecretName_NoFinding(t *testing.T) {
	f := findings027(t, `
variables:
  DEPLOY_ENV:
    value: "production"
`)
	if len(f) != 0 {
		t.Errorf("non-secret name should not be flagged, got %d", len(f))
	}
}

func TestGL027_SecretSuffixes(t *testing.T) {
	for _, name := range []string{
		"MY_TOKEN", "MY_SECRET", "MY_PASSWORD", "MY_PASSWD", "MY_PASS",
		"MY_PWD", "MY_KEY", "MY_CREDENTIAL", "MY_CERT", "MY_API_KEY",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			f := findings027(t, `
variables:
  `+name+`:
    value: "abc123"
`)
			if len(f) != 1 {
				t.Errorf("%s: expected 1 finding, got %d", name, len(f))
			}
		})
	}
}

func TestGL027_JobLevel(t *testing.T) {
	f := findings027(t, `
deploy:
  variables:
    DB_PASSWORD:
      value: "secret"
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for job-level variable, got %d", len(f))
	}
	if f[0].Job != "deploy" {
		t.Errorf("expected job name 'deploy', got %q", f[0].Job)
	}
}

func TestGL027_TopLevelMultiple(t *testing.T) {
	f := findings027(t, `
variables:
  PLAIN_VAR: "hello"
  API_TOKEN:
    value: "secret"
  DB_PASSWORD:
    value: "pw"
    masked: true
  SSH_KEY:
    value: "key"
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (API_TOKEN and SSH_KEY), got %d", len(f))
	}
}
