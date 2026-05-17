package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings006(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL006.Check(doc.Root, "test.yml")
}

func TestGL006_GitLabPAT(t *testing.T) {
	f := findings006(t, `
variables:
  DEPLOY_TOKEN: "glpat-xxxxxxxxxxxxxxxxxxxx"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
}

func TestGL006_AWSAccessKey(t *testing.T) {
	f := findings006(t, `
variables:
  AWS_SECRET: "AKIAIOSFODNN7EXAMPLE"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for AWS key, got %d", len(f))
	}
}

func TestGL006_PEMKey(t *testing.T) {
	f := findings006(t, `
variables:
  SIGNING_KEY: "-----BEGIN RSA PRIVATE KEY-----"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for PEM key, got %d", len(f))
	}
}

func TestGL006_GitHubPAT(t *testing.T) {
	f := findings006(t, `
variables:
  GH_TOKEN: "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for GitHub PAT, got %d", len(f))
	}
}

func TestGL006_SlackToken(t *testing.T) {
	f := findings006(t, `
variables:
  SLACK_BOT: "xoxb-FAKETOKEN-NOTREAL"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for Slack token, got %d", len(f))
	}
}

func TestGL006_OpenAIProjectKey(t *testing.T) {
	f := findings006(t, `
variables:
  OPENAI_KEY: "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for OpenAI project API key, got %d", len(f))
	}
}

func TestGL006_VariableReference_NoFinding(t *testing.T) {
	f := findings006(t, `
variables:
  AWS_SECRET: "$AWS_SECRET_FROM_VAULT"
build:
  script: [echo ok]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for variable reference, got %d", len(f))
	}
}

func TestGL006_SafeValue_NoFinding(t *testing.T) {
	f := findings006(t, `
variables:
  REGION: "us-east-1"
  LOG_LEVEL: "info"
build:
  script: [echo ok]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for safe values, got %d", len(f))
	}
}

func TestGL006_PerJobVariables(t *testing.T) {
	f := findings006(t, `
deploy:
  variables:
    DEPLOY_TOKEN: "glpat-xxxxxxxxxxxxxxxxxxxx"
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in per-job variables, got %d", len(f))
	}
}

func TestGL006_ExtendedForm(t *testing.T) {
	f := findings006(t, `
variables:
  API_KEY:
    value: "glpat-xxxxxxxxxxxxxxxxxxxx"
    description: "deploy token"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for extended variable form, got %d", len(f))
	}
}

func TestGL006_EmptyValue_NoFinding(t *testing.T) {
	f := findings006(t, `
variables:
  OPTIONAL_TOKEN: ""
build:
  script: [echo ok]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for empty value, got %d", len(f))
	}
}

func TestGL006_MultipleSecrets(t *testing.T) {
	f := findings006(t, `
variables:
  PAT: "glpat-xxxxxxxxxxxxxxxxxxxx"
  AWS: "AKIAIOSFODNN7EXAMPLE"
build:
  script: [echo ok]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL006_LineNumber(t *testing.T) {
	f := findings006(t, `
variables:
  TOKEN: "glpat-xxxxxxxxxxxxxxxxxxxx"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
