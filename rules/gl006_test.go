// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

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

// anchoredFormatCases returns one sample per token format, with the label
// GL006 reports for it. GL088 checks the same samples in script lines.
//
// Values are assembled from split literals + strings.Repeat so no contiguous
// token ever appears in source — otherwise GitHub push protection blocks the
// push (fixtures cannot split literals, so these formats live in unit tests).
func anchoredFormatCases() map[string]struct {
	value string
	label string
} {
	a := func(n int) string { return strings.Repeat("a", n) }
	return map[string]struct {
		value string
		label string
	}{
		"age":           {"AGE-SECRET-KEY-1" + strings.Repeat("A", 58), "age secret key"},
		"clojars":       {"CLOJARS_" + a(60), "Clojars deploy token"},
		"dynatrace":     {"dt0c01." + strings.Repeat("A", 24) + "." + strings.Repeat("B", 64), "Dynatrace token"},
		"duffel":        {"duffel_" + "test_" + a(43), "Duffel API token"},
		"frameio":       {"fio-u-" + a(64), "Frame.io token"},
		"terraform":     {a(14) + ".atlasv1." + strings.Repeat("b", 70), "Terraform Cloud token"},
		"linear":        {"lin_" + "api_" + a(40), "Linear API key"},
		"nrjs":          {"NRJS-" + a(19), "New Relic browser key"},
		"pulumi":        {"pul-" + a(40), "Pulumi access token"},
		"shippo":        {"shippo_" + "live_" + a(40), "Shippo API token"},
		"slack":         {"https://hooks.slack.com/services/T" + strings.Repeat("A", 9) + "/B" + strings.Repeat("A", 9) + "/" + a(24), "Slack webhook URL"},
		"alibaba":       {"LTAI" + a(20), "Alibaba access key ID"},
		"packagist":     {"packagist_" + "uip_" + a(68), "Private Packagist token"},
		"adobe":         {"p8e-" + a(32), "Adobe client secret"},
		"flutterwave":   {"FLW" + "SECK_TEST-" + a(32) + "-X", "Flutterwave secret key"},
		"cf user":       {"cfu" + "t_" + strings.Repeat("A", 40) + "0123abcd", "Cloudflare API token"},
		"cf account":    {"cfa" + "t_" + strings.Repeat("Ab1", 13) + "x" + "0123abcd", "Cloudflare API token"},
		"cf originca":   {"v1.0-" + a(24) + "-" + strings.Repeat("b", 146), "Cloudflare Origin CA key"},
		"bbdc":          {"BBD" + "C-" + strings.Repeat("Ab+/", 11), "Bitbucket Data Center token"},
		"nuget":         {"oy" + "2a" + "bcdefghijklmn23" + "q" + "rstuvwxyz234567abcdefghij" + "e", "NuGet API key"},
		"nuget upper":   {"OY" + "2A" + "BCDEFGHIJKLMN23" + "Q" + "RSTUVWXYZ234567ABCDEFGHIJ" + "E", "NuGet API key"},
		"sonar user":    {"sq" + "u_" + strings.Repeat("0123456789abcdef", 2) + "01234567", "SonarQube token"},
		"sonar project": {"sq" + "p_" + strings.Repeat("0123456789abcdef", 2) + "01234567", "SonarQube token"},
		"sonar global":  {"sq" + "a_" + strings.Repeat("0123456789abcdef", 2) + "01234567", "SonarQube token"},
		"ts auth":       {"tskey-" + "auth-" + "k" + "Ab12Cd34" + "CNTRL-" + strings.Repeat("a", 32), "Tailscale auth key"},
		"ts api":        {"tskey-" + "api-" + "k" + "Xy98" + "CNTRL-" + strings.Repeat("b", 28), "Tailscale API key"},
		"ts oauth":      {"tskey-" + "client-" + "k" + "QwErTy12" + "CNTRL-" + strings.Repeat("c", 40), "Tailscale OAuth client secret"},
		"infisical":     {"s" + "t." + "01234567" + "-" + "89ab" + "-" + "cdef" + "-" + "0123" + "-" + "456789abcdef" + "." + strings.Repeat("0123456789abcdef", 2), "Infisical service token"},
		"infisical rot": {"s" + "t." + "01234567" + "-" + "89ab" + "-" + "cdef" + "-" + "0123" + "-" + "456789abcdef" + "." + strings.Repeat("0123456789abcdef", 2) + "." + strings.Repeat("fedcba9876543210", 2), "Infisical service token"},
	}
}

func TestGL006_AnchoredFormatsExtra(t *testing.T) {
	cases := anchoredFormatCases()
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

func TestGL006_CloudflareBitbucketNearMiss_NoFinding(t *testing.T) {
	values := []string{
		"cfa" + "t_" + strings.Repeat("A", 40),                             // no checksum
		"cfa" + "t_" + strings.Repeat("A", 40) + "0123ABCD",                // checksum not lowercase hex
		"cfx" + "t_" + strings.Repeat("A", 40) + "0123abcd",                // unknown prefix
		"mycfa" + "t_" + strings.Repeat("A", 40) + "0123abcd",              // prefix inside a word
		"v1.0-" + strings.Repeat("a", 24) + "-" + strings.Repeat("b", 145), // short
		"BBD" + "C-" + strings.Repeat("A", 31),                             // short
		"$CF_API_TOKEN",
	}
	for _, v := range values {
		f := findings006(t, fmt.Sprintf(`
variables:
  TOKEN: "%s"
build:
  script: [echo ok]
`, v))
		if len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d", v, len(f))
		}
	}
}

func TestGL006_NuGetNearMiss_NoFinding(t *testing.T) {
	const mid = "bcdefghijklmn23"
	const tail = "rstuvwxyz234567abcdefghij"
	values := []string{
		"oy" + "2a" + mid + "q" + tail,                     // 45 chars
		"oy" + "2a" + mid + "q" + tail + "ea",              // 47 chars
		"oy" + "2a" + "bcdefghijklmn01" + "q" + tail + "e", // 0/1 are not base32
		"oy" + "2a" + "bcdefghijklmn89" + "q" + tail + "e", // 8/9 are not base32
		"oy" + "2z" + mid + "q" + tail + "e",               // 4th char outside [a-p]
		"oy" + "2a" + mid + "b" + tail + "e",               // 20th char outside [aq]
		"oy" + "2a" + mid + "q" + tail + "b",               // last char outside [aeimquy4]
		"x" + "oy" + "2a" + mid + "q" + tail + "e",         // inside a longer token
		"$NUGET_API_KEY",
	}
	for _, v := range values {
		f := findings006(t, fmt.Sprintf(`
variables:
  NUGET_API_KEY: "%s"
build:
  script: [echo ok]
`, v))
		if len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d", v, len(f))
		}
	}
}

func TestGL006_SonarQubeNearMiss_NoFinding(t *testing.T) {
	const hex = "0123456789abcdef0123456789abcdef0123456"
	values := []string{
		"sq" + "u_" + hex,                      // 39 hex chars
		"sq" + "u_" + hex + "78",               // 41 hex chars
		"sq" + "u_" + strings.ToUpper(hex+"7"), // uppercase hex
		"sq" + "x_" + hex + "7",                // unknown prefix
		"$SONAR_TOKEN",
	}
	for _, v := range values {
		f := findings006(t, fmt.Sprintf(`
variables:
  SONAR_TOKEN: "%s"
build:
  script: [echo ok]
`, v))
		if len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d", v, len(f))
		}
	}
}

func TestGL006_TailscaleInfisicalNearMiss_NoFinding(t *testing.T) {
	values := []string{
		"tskey-" + "auth-xxxx", // placeholder from issue #794, no key segment
		"tskey-" + "auth-" + "k" + "Ab12" + "CNTRL-" + strings.Repeat("a", 27),                                                      // tail too short
		"tskey-" + "auth-" + "k" + "Ab" + "CNTRL-" + strings.Repeat("a", 32),                                                        // middle segment too short
		"tskey-" + "api-" + "k" + "Ab12Cd34" + "CNTRL-" + strings.Repeat("a", 41),                                                   // tail too long
		"s" + "t." + "01234567" + "-" + "89ab" + "-" + "cdef" + "-" + "0123" + "-" + "456789abcdef" + "." + strings.Repeat("0", 31), // Infisical secret too short
		"s" + "t." + "01234567" + "-" + "89ab" + "-" + "cdef" + "-" + "0123" + "-" + "456789abcdef",                                 // Infisical secret missing
		"$TS_AUTHKEY",
	}
	for _, v := range values {
		f := findings006(t, fmt.Sprintf(`
variables:
  TOKEN: "%s"
build:
  script: [echo ok]
`, v))
		if len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d", v, len(f))
		}
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

// gitlabTokens are the GitLab token formats of #925, each built from its
// prefix and a body of the format's length, split so no contiguous token is
// in the source (GitHub push protection).
var gitlabTokens = []struct {
	name, prefix, alphabet string
	n                      int
}{
	{"GitLab pipeline trigger token", "glp" + "tt-", "0123456789abcdef", 40},
	{"GitLab feed token", "gl" + "ft-", "aB3_x-9Qz7", 20},
	{"GitLab OAuth application secret", "glo" + "as-", "aB3_x-9Qz7", 64},
	{"GitLab Kubernetes agent token", "glag" + "ent-", "aB3_x-9Qz7", 50},
	{"GitLab incoming mail token", "gli" + "mt-", "aB3_x-9Qz7", 25},
	{"GitLab feature flag client token", "glff" + "ct-", "aB3_x-9Qz7", 20},
	{"GitLab SCIM token", "glso" + "at-", "aB3_x-9Qz7", 20},
	{"GitLab runner registration token (legacy)", "GR13" + "48941", "aB3_x-9Qz7", 20},
}

func tokenBody(alphabet string, n int) string {
	return strings.Repeat(alphabet, n/len(alphabet)+1)[:n]
}

func TestGL006_GitLabTokenFormats(t *testing.T) {
	for _, tc := range gitlabTokens {
		t.Run(tc.name, func(t *testing.T) {
			token := tc.prefix + tokenBody(tc.alphabet, tc.n)
			f := findings006(t, "variables:\n  VALUE: \""+token+"\"\nbuild:\n  script: [echo ok]\n")
			if len(f) != 1 || !strings.Contains(f[0].Message, tc.name) {
				t.Errorf("%s: got %v, want one %s finding", token, f, tc.name)
			}
			for _, quiet := range []string{
				tc.prefix + tokenBody(tc.alphabet, tc.n-1),          // one character short
				tc.prefix + tokenBody("EXAMPLE", tc.n),              // placeholder
				tc.prefix + strings.Repeat("e", tc.n-7) + "example", // placeholder in the alphabet
			} {
				if f := findings006(t, "variables:\n  VALUE: \""+quiet+"\"\nbuild:\n  script: [echo ok]\n"); len(f) != 0 {
					t.Errorf("%s: got %v, want no finding", quiet, f)
				}
			}
		})
	}
}

func TestGL006_GitLabSessionCookie(t *testing.T) {
	cookie := "_gitlab_" + "session=" + tokenBody("0123456789abcdefghijklmnopqrstuvwxyz", 32)
	f := findings006(t, "variables:\n  COOKIE: \"Cookie: "+cookie+"; path=/\"\nbuild:\n  script: [echo ok]\n")
	if len(f) != 1 || !strings.Contains(f[0].Message, "GitLab session cookie") {
		t.Errorf("got %v, want one session cookie finding", f)
	}
	short := "_gitlab_" + "session=" + tokenBody("0123456789abcdef", 31)
	if f := findings006(t, "variables:\n  COOKIE: \"Cookie: "+short+"\"\nbuild:\n  script: [echo ok]\n"); len(f) != 0 {
		t.Errorf("31 characters: got %v, want no finding", f)
	}
}

// GL088 finds the same tokens on a script line, such as a pipeline trigger
// token sent with curl.
func TestGL088_GitLabTokenFormats(t *testing.T) {
	for _, tc := range gitlabTokens {
		token := tc.prefix + tokenBody(tc.alphabet, tc.n)
		f := findings088(t, "trigger:\n  script:\n    - curl -X POST -F token="+token+" -F ref=main \"$CI_API_V4_URL/projects/1/trigger/pipeline\"\n")
		if len(f) != 1 || !strings.Contains(f[0].Message, tc.name) {
			t.Errorf("%s: got %v, want one %s finding", tc.name, f, tc.name)
		}
	}
	cookie := "_gitlab_" + "session=" + tokenBody("0123456789abcdefghijklmnopqrstuvwxyz", 32)
	if f := findings088(t, "job:\n  script:\n    - |\n      curl -H 'Cookie: "+cookie+"' https://gitlab.example.com/api/v4/user\n"); len(f) != 1 {
		t.Errorf("session cookie: got %v, want one finding", f)
	}
}
