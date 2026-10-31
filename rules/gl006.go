// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl006 struct{}

var GL006 = &gl006{}

func (r *gl006) ID() string { return "GL006" }

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"GitLab PAT", regexp.MustCompile(`^glpat-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab CI job token", regexp.MustCompile(`^glcbt-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab runner registration token", regexp.MustCompile(`^glrt-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab deploy token", regexp.MustCompile(`^gldt-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab pipeline trigger token", regexp.MustCompile(`^glptt-[0-9a-f]{40}$`)},
	{"GitLab feed token", regexp.MustCompile(`^glft-[0-9a-zA-Z_-]{20}$`)},
	{"GitLab OAuth application secret", regexp.MustCompile(`^gloas-[0-9a-zA-Z_-]{64}$`)},
	{"GitLab Kubernetes agent token", regexp.MustCompile(`^glagent-[0-9a-zA-Z_-]{50}$`)},
	{"GitLab incoming mail token", regexp.MustCompile(`^glimt-[0-9a-zA-Z_-]{25}$`)},
	{"GitLab feature flag client token", regexp.MustCompile(`^glffct-[0-9a-zA-Z_-]{20}$`)},
	{"GitLab SCIM token", regexp.MustCompile(`^glsoat-[0-9a-zA-Z_-]{20}$`)},
	{"GitLab runner registration token (legacy)", regexp.MustCompile(`^GR1348941[0-9a-zA-Z_-]{20}$`)},
	// A session cookie sits inside a longer value, such as a Cookie header.
	{"GitLab session cookie", regexp.MustCompile(`_gitlab_session=[0-9a-z]{32}`)},
	// AWS key-id prefixes: long-term (AKIA), temporary STS session (ASIA),
	// the older A3T form, ABIA (STS service bearer token), ACCA (context-
	// specific credential) and the various IAM resource-id prefixes.
	{"AWS access key", regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}`)},
	{"Google API key", regexp.MustCompile(`^AIza[0-9A-Za-z_-]{35}$`)},
	// Azure AD (Entra ID) client secrets carry Q~ after a version digit.
	{"Azure AD client secret", regexp.MustCompile(`^[A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34}$`)},
	{"PEM private key", regexp.MustCompile(`-----BEGIN (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)`)},
	{"GitHub PAT", regexp.MustCompile(`^ghp_[A-Za-z0-9]{36,}$`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{82,}$`)},
	// Covers both the fixed-length ghs_<36+> form and the newer stateless
	// ghs_<APPID>_<JWT> form (the JWT segment adds '.' separators).
	{"GitHub App installation token", regexp.MustCompile(`^ghs_[A-Za-z0-9_.-]{36,}$`)},
	{"GitHub OAuth/user/refresh token", regexp.MustCompile(`^gh[uor]_[A-Za-z0-9]{36,}$`)},
	// Also the configuration access (xoxe.xoxb-, xoxe.xoxp-) and refresh
	// (xoxe-) tokens of the app configuration API.
	{"Slack token", regexp.MustCompile(`^(?:xox[baprs]-[A-Za-z0-9-]{10,}|xoxe\.xox[bp]-[0-9]-[A-Za-z0-9]{163,166}|xoxe-[0-9]-[A-Za-z0-9]{146})$`)},
	{"Slack app-level token", regexp.MustCompile(`^xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+$`)},
	{"Docker Hub access token", regexp.MustCompile(`^dckr_(?:pat|oat)_[A-Za-z0-9_-]{20,}$`)},
	// Anthropic and OpenRouter reuse the sk- prefix but carry no OpenAI
	// watermark; match them by their specific prefixes so they are labelled
	// correctly instead of being reported as OpenAI keys.
	{"Anthropic API key", regexp.MustCompile(`^sk-ant-[A-Za-z0-9_-]{20,}$`)},
	{"OpenRouter API key", regexp.MustCompile(`^sk-or-v1-[A-Za-z0-9]{20,}$`)},
	// Modern OpenAI keys embed the fixed watermark T3BlbkFJ (base64 of "OpenAI")
	// between two random segments. Requiring it cuts false positives from
	// arbitrary sk-… strings and avoids mislabelling other vendors' keys.
	{"OpenAI project API key", regexp.MustCompile(`^sk-proj-[A-Za-z0-9_-]{8,}T3BlbkFJ[A-Za-z0-9_-]{8,}$`)},
	{"OpenAI service/admin API key", regexp.MustCompile(`^sk-(?:svcacct|admin|service)-[A-Za-z0-9_-]{8,}T3BlbkFJ[A-Za-z0-9_-]{8,}$`)},
	{"OpenAI API key", regexp.MustCompile(`^sk-[A-Za-z0-9]{8,}T3BlbkFJ[A-Za-z0-9]{8,}$`)},
	{"OpenAI realtime client secret", regexp.MustCompile(`^ek_[0-9a-f]{32,}$`)},
	{"PyPI upload token", regexp.MustCompile(`^pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}$`)},
	{"npm access token", regexp.MustCompile(`^npm_[A-Za-z0-9]{36}$`)},
	// sk_ secret and rk_ restricted keys.
	{"Stripe secret key", regexp.MustCompile(`^[rs]k_(?:test|live|prod)_[A-Za-z0-9]{24,}$`)},
	{"HuggingFace token", regexp.MustCompile(`^hf_[A-Za-z0-9]{34,40}$`)},
	{"HuggingFace organization token", regexp.MustCompile(`^api_org_[A-Za-z]{34}$`)},
	{"GCP service account key", regexp.MustCompile(`"type":\s*"service_account"`)},
	{"Databricks token", regexp.MustCompile(`^dapi[a-h0-9]{32}$`)},
	{"Doppler token", regexp.MustCompile(`^dp\.pt\.[A-Za-z0-9]{43}$`)},
	{"SendGrid API key", regexp.MustCompile(`^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$`)},
	{"PlanetScale token", regexp.MustCompile(`^pscale_(?:pw|tkn)_[A-Za-z0-9_.-]{32,}$`)},
	{"PlanetScale OAuth token", regexp.MustCompile(`^pscale_oauth_[A-Za-z0-9_.=-]{32,64}$`)},
	{"Postman API key", regexp.MustCompile(`^PMAK-[a-f0-9]{24}-[a-f0-9]{34}$`)},
	{"RubyGems API key", regexp.MustCompile(`^rubygems_[a-f0-9]{48}$`)},
	{"New Relic API key", regexp.MustCompile(`^NRAK-[A-Z0-9]{27}$`)},
	{"Shopify access token", regexp.MustCompile(`^shp(?:ss|at|ca|pa)_[a-fA-F0-9]{32}$`)},
	{"Brevo (Sendinblue) API key", regexp.MustCompile(`^xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}$`)},
	{"age secret key", regexp.MustCompile(`^AGE-SECRET-KEY-1[0-9A-Z]{50,}$`)},
	{"Clojars deploy token", regexp.MustCompile(`^CLOJARS_[a-z0-9]{60}$`)},
	{"Dynatrace token", regexp.MustCompile(`^dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}$`)},
	{"Duffel API token", regexp.MustCompile(`^duffel_(?:test|live)_[A-Za-z0-9_-]{40,}$`)},
	{"Frame.io token", regexp.MustCompile(`^fio-u-[A-Za-z0-9_-]{64}$`)},
	{"Terraform Cloud token", regexp.MustCompile(`[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}`)},
	{"Linear API key", regexp.MustCompile(`^lin_api_[A-Za-z0-9]{40}$`)},
	{"New Relic browser key", regexp.MustCompile(`^NRJS-[a-f0-9]{19}$`)},
	{"Pulumi access token", regexp.MustCompile(`^pul-[a-f0-9]{40}$`)},
	{"Shippo API token", regexp.MustCompile(`^shippo_(?:live|test)_[a-f0-9]{40}$`)},
	// Incoming webhooks under /services/, and workflow and trigger webhooks
	// of Slack's Workflow Builder.
	{"Slack webhook URL", regexp.MustCompile(`^https://hooks\.slack\.com/(?:services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]{20,}|(?:workflows|triggers)/T[A-Za-z0-9_]+/(?:[A-Za-z0-9_]+/)+[A-Za-z0-9_]{20,})$`)},
	{"Alibaba access key ID", regexp.MustCompile(`^LTAI[A-Za-z0-9]{20}$`)},
	{"Private Packagist token", regexp.MustCompile(`^packagist_[a-z]{3}_[a-f0-9]{68}$`)},
	{"Adobe client secret", regexp.MustCompile(`^p8e-[a-z0-9]{32}$`)},
	{"Flutterwave secret key", regexp.MustCompile(`^FLW(?:PUBK|SECK)_TEST-[a-h0-9]{32}-X$`)},
	// cfut_ (user) and cfat_ (account) tokens end in an 8-hex checksum.
	{"Cloudflare API token", regexp.MustCompile(`^cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}$`)},
	{"Cloudflare Origin CA key", regexp.MustCompile(`^v1\.0-[a-f0-9]{24}-[a-f0-9]{146}$`)},
	{"Bitbucket Data Center token", regexp.MustCompile(`^BBDC-[A-Za-z0-9+/=]{32,}$`)},
	// base32 after the oy2 prefix; the 4th, 20th and last characters carry
	// fixed bits, which keeps random lowercase strings from matching.
	{"NuGet API key", regexp.MustCompile(`(?i)^oy2[a-p][a-z2-7]{15}[aq][a-z2-7]{25}[aeimquy4]$`)},
	// squ_ user, sqp_ project analysis and sqa_ global analysis tokens.
	{"SonarQube token", regexp.MustCompile(`^sq[apu]_[0-9a-f]{40}$`)},
	// Tailscale keys: tskey-<kind>-k<4-16 alnum>CNTRL-<28-40 alnum>.
	{"Tailscale auth key", regexp.MustCompile(`^tskey-auth-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40}$`)},
	{"Tailscale API key", regexp.MustCompile(`^tskey-api-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40}$`)},
	{"Tailscale OAuth client secret", regexp.MustCompile(`^tskey-client-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40}$`)},
	// Infisical service token: st.<uuid>.<32 hex>, with an optional second
	// 32 hex segment after rotation.
	{"Infisical service token", regexp.MustCompile(`^st\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[0-9a-f]{32}(\.[0-9a-f]{32})?$`)},
	// do_v1_ personal access, doo_v1_ OAuth and dor_v1_ refresh tokens.
	{"DigitalOcean token", regexp.MustCompile(`^do[opr]_v1_[a-f0-9]{64}$`)},
	{"HashiCorp Vault service token", regexp.MustCompile(`^hvs\.[A-Za-z0-9_-]{90,120}$`)},
	{"HashiCorp Vault batch token", regexp.MustCompile(`^hvb\.[A-Za-z0-9_-]{138,300}$`)},
	{"JFrog API key", regexp.MustCompile(`^AKCp[A-Za-z0-9]{69}$`)},
	// A reference token is base64 starting with "ref".
	{"JFrog reference token", regexp.MustCompile(`^cmVmd[A-Za-z0-9]{59}$`)},
	{"Heroku API key", regexp.MustCompile(`^HRKU-AA[0-9A-Za-z_-]{58}$`)},
	{"Fly.io token", regexp.MustCompile(`^fo1_[A-Za-z0-9_-]{43}$`)},
	// flyctl prints macaroon tokens as "FlyV1 fm2_…", several joined by commas.
	{"Fly.io macaroon token", regexp.MustCompile(`^(?:FlyV1 )?fm2_[A-Za-z0-9+/]{100,}={0,3}(?:,fm2_[A-Za-z0-9+/]+={0,3})*$`)},
	{"Grafana Cloud token", regexp.MustCompile(`^glc_[A-Za-z0-9+/]{32,400}={0,3}$`)},
	{"Grafana service account token", regexp.MustCompile(`^glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}$`)},
	// The legacy API key is base64 JSON starting with {"k":".
	{"Grafana API key", regexp.MustCompile(`^eyJrIjoi[A-Za-z0-9]{70,400}={0,3}$`)},
	{"Sentry user token", regexp.MustCompile(`^sntryu_[a-f0-9]{64}$`)},
	{"Sentry organization token", regexp.MustCompile(`^sntrys_eyJpYXQiO[A-Za-z0-9+/=_-]{50,}$`)},
	{"1Password service account token", regexp.MustCompile(`^ops_eyJ[A-Za-z0-9+/]{250,}={0,3}$`)},
	{"OpenShift user token", regexp.MustCompile(`^sha256~[A-Za-z0-9_-]{43}$`)},
	{"AWS Bedrock API key", regexp.MustCompile(`^ABSK[A-Za-z0-9+/]{109,269}={0,2}$`)},
	{"Notion integration token", regexp.MustCompile(`^ntn_[0-9]{11}[A-Za-z0-9]{35}$`)},
	{"Perplexity API key", regexp.MustCompile(`^pplx-[A-Za-z0-9]{48}$`)},
	{"Prefect API key", regexp.MustCompile(`^pnu_[A-Za-z0-9]{36}$`)},
	{"ReadMe API key", regexp.MustCompile(`^rdme_[a-z0-9]{70}$`)},
	{"Infracost API key", regexp.MustCompile(`^ico-[A-Za-z0-9]{32}$`)},
	{"Scalingo API token", regexp.MustCompile(`^tk-us-[A-Za-z0-9_-]{48}$`)},
	{"Sourcegraph access token", regexp.MustCompile(`^sgp_(?:[a-f0-9]{16}|local)_[a-f0-9]{40}$`)},
	{"Microsoft Teams webhook URL", regexp.MustCompile(`^https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/IncomingWebhook/[0-9a-f]{32}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/[A-Za-z0-9_-]+)?$`)},
	// Mapbox secret access token (sk.); public tokens (pk.) are intentionally
	// excluded because they are published in client-side code.
	{"Mapbox secret access token", regexp.MustCompile(`^sk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw]$`)},
	// Harness platform API key: pat.<account>.<id>.<token> or sat.<...>.
	{"Harness API key", regexp.MustCompile(`^(?:pat|sat)\.[A-Za-z0-9_-]{22}\.[0-9a-f]{24}\.[A-Za-z0-9]{20}$`)},
	// Atlassian API token (Jira/Confluence/Bitbucket Cloud).
	{"Atlassian API token", regexp.MustCompile(`^ATATT3[A-Za-z0-9_=\-]{180,}$`)},
}

func (r *gl006) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		for _, f := range checkVariablesNode(vars, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})

	return findings
}

func checkVariablesNode(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		varName := node.Content[i].Value
		val := node.Content[i+1]

		var scalar *yaml.Node
		switch val.Kind {
		case yaml.ScalarNode:
			scalar = val
		case yaml.MappingNode:
			// Extended form: {value: ..., description: ...}
			if v := parser.FindKey(val, "value"); v != nil && v.Kind == yaml.ScalarNode {
				scalar = v
			}
		}
		if scalar == nil {
			continue
		}
		if f := checkSecretValue(scalar, varName, file); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

// placeholderMarkers are substrings (matched case-insensitively) that mark a
// value as an obvious documentation/template placeholder rather than a real
// secret, e.g. "glpat-EXAMPLE…" or "AKIA…EXAMPLE…". A matched value containing
// one of these is skipped to avoid firing on example configs.
var placeholderMarkers = []string{"example", "placeholder", "changeme", "redacted", "your-token-here", "your_token_here"}

// placeholderShapeRe matches whole values written as a placeholder (#991):
// <your token>, _api_token_, {{ token }}, xxx…, TODO, replace-me.
var placeholderShapeRe = regexp.MustCompile(`(?i)^(?:<[^<>]+>|_[a-z0-9_-]+_|\{\{[^{}]+\}\}|x{3,}|\*{3,}|todo|tbd|replace[-_ ]?me|set[-_ ]?me)$`)

func looksLikePlaceholder(v string) bool {
	lower := strings.ToLower(v)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return placeholderShapeRe.MatchString(strings.Trim(v, `"'`))
}

func checkSecretValue(node *yaml.Node, varName, file string) *finding.Finding {
	v := node.Value
	if v == "" || strings.HasPrefix(v, "$") || looksLikePlaceholder(v) {
		return nil
	}
	for _, pat := range secretPatterns {
		if pat.re.MatchString(v) {
			f := finding.Finding{
				RuleID:   "GL006",
				Severity: finding.Error,
				Message: fmt.Sprintf(
					"variable %q appears to contain a hardcoded %s — use GitLab CI/CD masked variables (Settings → CI/CD → Variables) instead",
					varName, pat.name,
				),
				File: file,
				Line: node.Line,
				Col:  node.Column,
			}
			return &f
		}
	}
	return nil
}

// TokenPatterns returns GL006's token formats without their ^…$ anchors, to
// find a token inside a longer text such as a source line or a message
// (#831). The PEM and GCP service account entries are markers next to a
// secret, not the secret itself, and are left out.
func TokenPatterns() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range secretPatterns {
		if p.name == "PEM private key" || p.name == "GCP service account key" {
			continue
		}
		src := p.re.String()
		flags := ""
		if strings.HasPrefix(src, "(?i)") {
			flags, src = "(?i)", strings.TrimPrefix(src, "(?i)")
		}
		src = strings.TrimSuffix(strings.TrimPrefix(src, "^"), "$")
		out = append(out, regexp.MustCompile(flags+src))
	}
	return out
}
