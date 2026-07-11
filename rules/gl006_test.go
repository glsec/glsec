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
	// Split literal so the contiguous key never appears in source (push protection);
	// a non-"example" value so the placeholder allowlist does not suppress it.
	key := "AKIA" + strings.Repeat("Q", 16)
	f := findings006(t, fmt.Sprintf(`
variables:
  AWS_SECRET: "%s"
build:
  script: [echo ok]
`, key))
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
	// wm is the OpenAI watermark, split so the marker is not contiguous in source.
	wm := "T3Blbk" + "FJ"
	body := strings.Repeat("a", 12)
	svc := "sk-svcacct-" + body + wm + body
	admin := "sk-admin-" + body + wm + body
	service := "sk-service-myapp-" + body + wm + body
	f := findings006(t, fmt.Sprintf(`
variables:
  SVC: "%s"
  ADMIN: "%s"
  SERVICE: "%s"
build:
  script: [echo ok]
`, svc, admin, service))
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
	key := "ASIA" + strings.Repeat("Q", 16)
	f := findings006(t, fmt.Sprintf(`
variables:
  AWS_SESSION: "%s"
build:
  script: [echo ok]
`, key))
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
	wm := "T3Blbk" + "FJ"
	key := "sk-proj-" + strings.Repeat("a", 40) + wm + strings.Repeat("a", 40)
	f := findings006(t, fmt.Sprintf(`
variables:
  OPENAI_KEY: "%s"
build:
  script: [echo ok]
`, key))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for OpenAI project API key, got %d", len(f))
	}
}

func TestGL006_OpenAIKeyRequiresWatermark(t *testing.T) {
	wm := "T3Blbk" + "FJ"
	withMark := "sk-" + strings.Repeat("a", 20) + wm + strings.Repeat("a", 20)
	f := findings006(t, fmt.Sprintf(`
variables:
  OPENAI_KEY: "%s"
build:
  script: [echo ok]
`, withMark))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for watermarked OpenAI key, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "OpenAI") {
		t.Errorf("expected OpenAI in message, got %q", f[0].Message)
	}

	// Same shape without the watermark must not be reported as an OpenAI key.
	noMark := "sk-" + strings.Repeat("a", 44)
	f = findings006(t, fmt.Sprintf(`
variables:
  NOT_OPENAI: "%s"
build:
  script: [echo ok]
`, noMark))
	if len(f) != 0 {
		t.Fatalf("expected no finding for sk- value without watermark, got %d", len(f))
	}
}

func TestGL006_AnthropicKeyNotOpenAI(t *testing.T) {
	f := findings006(t, `
variables:
  ANTHROPIC_KEY: "sk-ant-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for Anthropic key, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "Anthropic") {
		t.Errorf("expected Anthropic in message, got %q", f[0].Message)
	}
}

func TestGL006_OpenRouterKeyNotOpenAI(t *testing.T) {
	f := findings006(t, `
variables:
  OPENROUTER_KEY: "sk-or-v1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for OpenRouter key, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "OpenRouter") {
		t.Errorf("expected OpenRouter in message, got %q", f[0].Message)
	}
}

func TestGL006_AnchoredFormatsExtra(t *testing.T) {
	// Values are assembled from split literals + strings.Repeat so no contiguous
	// token ever appears in source — otherwise GitHub push protection blocks the
	// push (fixtures cannot split literals, so these formats live in unit tests).
	a := func(n int) string { return strings.Repeat("a", n) }
	cases := map[string]struct {
		value string
		label string
	}{
		"age":         {"AGE-SECRET-KEY-1" + strings.Repeat("A", 58), "age secret key"},
		"clojars":     {"CLOJARS_" + a(60), "Clojars deploy token"},
		"dynatrace":   {"dt0c01." + strings.Repeat("A", 24) + "." + strings.Repeat("B", 64), "Dynatrace token"},
		"duffel":      {"duffel_" + "test_" + a(43), "Duffel API token"},
		"frameio":     {"fio-u-" + a(64), "Frame.io token"},
		"terraform":   {a(14) + ".atlasv1." + strings.Repeat("b", 70), "Terraform Cloud token"},
		"linear":      {"lin_" + "api_" + a(40), "Linear API key"},
		"nrjs":        {"NRJS-" + a(19), "New Relic browser key"},
		"pulumi":      {"pul-" + a(40), "Pulumi access token"},
		"shippo":      {"shippo_" + "live_" + a(40), "Shippo API token"},
		"slack":       {"https://hooks.slack.com/services/T" + strings.Repeat("A", 9) + "/B" + strings.Repeat("A", 9) + "/" + a(24), "Slack webhook URL"},
		"alibaba":     {"LTAI" + a(20), "Alibaba access key ID"},
		"packagist":   {"packagist_" + "uip_" + a(68), "Private Packagist token"},
		"adobe":       {"p8e-" + a(32), "Adobe client secret"},
		"flutterwave": {"FLW" + "SECK_TEST-" + a(32) + "-X", "Flutterwave secret key"},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			f := findings006(t, fmt.Sprintf(`
variables:
  TOKEN: "%s"
build:
  script: [echo ok]
`, tc.value))
			if len(f) != 1 {
				t.Fatalf("expected 1 finding for %s, got %d", name, len(f))
			}
			if !strings.Contains(f[0].Message, tc.label) {
				t.Errorf("expected %q in message, got %q", tc.label, f[0].Message)
			}
		})
	}
}

func TestGL006_PlaceholderExample_NoFinding(t *testing.T) {
	f := findings006(t, `
variables:
  AWS_SECRET: "AKIAIOSFODNN7EXAMPLE"
  GL_PAT: "glpat-EXAMPLEEXAMPLEEXAMPLE12"
  PLACEHOLDER: "glpat-your-token-here-000000"
build:
  script: [echo ok]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for placeholder values, got %d", len(f))
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
	aws := "AKIA" + strings.Repeat("Q", 16)
	f := findings006(t, fmt.Sprintf(`
variables:
  PAT: "glpat-xxxxxxxxxxxxxxxxxxxx"
  AWS: "%s"
build:
  script: [echo ok]
`, aws))
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
