package rules

import (
	"fmt"
	"strings"
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

func TestGL006_GitHubAppInstallationToken(t *testing.T) {
	f := findings006(t, `
variables:
  GHS_FIXED: "ghs_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  GHS_STATELESS: "ghs_1234_eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0In0.c2lnbmF0dXJlLXBhcnQtaGVyZQ"
build:
  script: [echo ok]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for ghs_ tokens, got %d", len(f))
	}
}

func TestGL006_OpenAIServiceAdminKey(t *testing.T) {
	f := findings006(t, `
variables:
  SVC: "sk-svcacct-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ADMIN: "sk-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  SERVICE: "sk-service-myapp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build:
  script: [echo ok]
`)
	if len(f) != 3 {
		t.Fatalf("expected 3 findings for OpenAI service/admin keys, got %d", len(f))
	}
}

func TestGL006_OpenAIRealtimeSecret(t *testing.T) {
	f := findings006(t, `
variables:
  RT: "ek_0123456789abcdef0123456789abcdef"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for OpenAI realtime client secret, got %d", len(f))
	}
}

func TestGL006_AWSTemporaryKey(t *testing.T) {
	f := findings006(t, `
variables:
  AWS_SESSION: "ASIAIOSFODNN7EXAMPLE"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for AWS STS session key, got %d", len(f))
	}
}

func TestGL006_GitHubOAuthTokens(t *testing.T) {
	f := findings006(t, `
variables:
  GHU: "ghu_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  GHO: "gho_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  GHR: "ghr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build:
  script: [echo ok]
`)
	if len(f) != 3 {
		t.Fatalf("expected 3 findings for gh{u,o,r}_ tokens, got %d", len(f))
	}
}

func TestGL006_Tier1Tokens(t *testing.T) {
	// Stripe keys are assembled from split literals so the contiguous token
	// never appears in source — otherwise GitHub push protection blocks the push.
	stripe := "sk_" + "live_" + strings.Repeat("a", 24)
	f := findings006(t, fmt.Sprintf(`
variables:
  PYPI: "pypi-AgEIcHlwaS5vcmcaaaaaaaaaaaaaaaaaaaaaaaa"
  NPM: "npm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  STRIPE: "%s"
  HF: "hf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build:
  script: [echo ok]
`, stripe))
	if len(f) != 4 {
		t.Fatalf("expected 4 findings for Tier-1 tokens, got %d", len(f))
	}
}

func TestGL006_GCPServiceAccount(t *testing.T) {
	f := findings006(t, `
variables:
  GCP_SA: |
    {
      "type": "service_account",
      "project_id": "my-project"
    }
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for GCP service account key, got %d", len(f))
	}
}

func TestGL006_Tier2Tokens(t *testing.T) {
	// Doppler and New Relic prefixes are split for the same push-protection reason.
	doppler := "dp." + "pt." + strings.Repeat("a", 43)
	newrelic := "NRAK" + "-" + strings.Repeat("A", 27)
	f := findings006(t, fmt.Sprintf(`
variables:
  DATABRICKS: "dapiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  DOPPLER: "%s"
  NEWRELIC: "%s"
  RUBYGEMS: "rubygems_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build:
  script: [echo ok]
`, doppler, newrelic))
	if len(f) != 4 {
		t.Fatalf("expected 4 findings for Tier-2 tokens, got %d", len(f))
	}
}

func TestGL006_StripeNotMistakenForOpenAI(t *testing.T) {
	// Stripe uses sk_ (underscore); must not be swallowed by the OpenAI sk- rule.
	stripe := "sk_" + "test_" + strings.Repeat("a", 24)
	f := findings006(t, fmt.Sprintf(`
variables:
  STRIPE: "%s"
build:
  script: [echo ok]
`, stripe))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for Stripe key, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "Stripe") {
		t.Errorf("expected Stripe in message, got %q", f[0].Message)
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
