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
	// re is prefiltered and compiled on first use: most token formats never
	// appear in a pipeline, and compiling all of them took a third of the
	// rules' start-up (#1329).
	re prefiltered
}

var secretPatterns = []secretPattern{
	{"GitLab PAT", mustCompilePrefiltered(`^glpat-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab CI job token", mustCompilePrefiltered(`^glcbt-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab runner authentication token", mustCompilePrefiltered(`^glrtr?-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab workspace token", mustCompilePrefiltered(`^glwt-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab deploy token", mustCompilePrefiltered(`^gldt-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab pipeline trigger token", mustCompilePrefiltered(`^glptt-[0-9a-f]{40}$`)},
	{"GitLab feed token", mustCompilePrefiltered(`^glft-[0-9a-zA-Z_-]{20}$`)},
	{"GitLab OAuth application secret", mustCompilePrefiltered(`^gloas-[0-9a-zA-Z_-]{64}$`)},
	{"GitLab Kubernetes agent token", mustCompilePrefiltered(`^glagent-[0-9a-zA-Z_-]{50}$`)},
	{"GitLab incoming mail token", mustCompilePrefiltered(`^glimt-[0-9a-zA-Z_-]{25}$`)},
	{"GitLab feature flag client token", mustCompilePrefiltered(`^glffct-[0-9a-zA-Z_-]{20}$`)},
	{"GitLab SCIM token", mustCompilePrefiltered(`^glsoat-[0-9a-zA-Z_-]{20}$`)},
	{"GitLab runner registration token (legacy)", mustCompilePrefiltered(`^GR1348941[0-9a-zA-Z_-]{20}$`)},
	// A session cookie sits inside a longer value, such as a Cookie header.
	{"GitLab session cookie", mustCompilePrefiltered(`_gitlab_session=[0-9a-z]{32}`)},
	// A pre-signed storage URL is a bearer credential until it expires. It sits
	// before "AWS access key" so an S3 URL is named for what it is, not for
	// the key id inside it (#1315). Each form needs its signature parameter
	// with a literal value: AWS SigV4, AWS SigV2 (key id and signature), Azure
	// SAS (sig after another SAS parameter), GCS V4 and V2.
	{"pre-signed storage URL", mustCompilePrefiltered(`^https?://[^\s"']*?(?:` +
		`[?&]X-Amz-Signature=[0-9a-f]{64}` +
		`|[?&]AWSAccessKeyId=(?:AKIA|ASIA)[0-9A-Z]{16}(?:&[^\s"'&]*)*&Signature=[A-Za-z0-9%+/=]{16,}` +
		`|[?&]Signature=[A-Za-z0-9%+/=]{16,}(?:&[^\s"'&]*)*&AWSAccessKeyId=(?:AKIA|ASIA)[0-9A-Z]{16}` +
		`|[?&](?:sv|se|sp|sr|st|spr|srt|ss|skoid|sktid)=[^\s"'&]*(?:&[^\s"'&]*)*&sig=[A-Za-z0-9%+/=]{20,}` +
		`|[?&]X-Goog-Signature=[0-9a-f]{64,}` +
		`|[?&]GoogleAccessId=[^\s"'&]+(?:&[^\s"'&]*)*&Signature=[A-Za-z0-9%+/=]{16,}` +
		`)[^\s"']*$`)},
	// AWS key-id prefixes: long-term (AKIA), temporary STS session (ASIA),
	// the older A3T form, ABIA (STS service bearer token), ACCA (context-
	// specific credential) and the various IAM resource-id prefixes.
	{"AWS access key", mustCompilePrefiltered(`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}`)},
	{"Google API key", mustCompilePrefiltered(`^AIza[0-9A-Za-z_-]{35}$`)},
	// Azure AD (Entra ID) client secrets carry Q~ after a version digit.
	{"Azure AD client secret", mustCompilePrefiltered(`^[A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34}$`)},
	{"PEM private key", mustCompilePrefiltered(`-----BEGIN (?:(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)`)},
	{"GitHub PAT", mustCompilePrefiltered(`^ghp_[A-Za-z0-9]{36,}$`)},
	{"GitHub fine-grained PAT", mustCompilePrefiltered(`^github_pat_[A-Za-z0-9_]{82,}$`)},
	// Covers both the fixed-length ghs_<36+> form and the newer stateless
	// ghs_<APPID>_<JWT> form (the JWT segment adds '.' separators).
	{"GitHub App installation token", mustCompilePrefiltered(`^ghs_[A-Za-z0-9_.-]{36,}$`)},
	{"GitHub OAuth/user/refresh token", mustCompilePrefiltered(`^gh[uor]_[A-Za-z0-9]{36,}$`)},
	// Also the configuration access (xoxe.xoxb-, xoxe.xoxp-) and refresh
	// (xoxe-) tokens of the app configuration API.
	{"Slack token", mustCompilePrefiltered(`^(?:xox[baprs]-[A-Za-z0-9-]{10,}|xoxe\.xox[bp]-[0-9]-[A-Za-z0-9]{163,166}|xoxe-[0-9]-[A-Za-z0-9]{146})$`)},
	{"Slack app-level token", mustCompilePrefiltered(`^xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+$`)},
	{"Docker Hub access token", mustCompilePrefiltered(`^dckr_(?:pat|oat)_[A-Za-z0-9_-]{20,}$`)},
	// Anthropic and OpenRouter reuse the sk- prefix but carry no OpenAI
	// watermark; match them by their specific prefixes so they are labelled
	// correctly instead of being reported as OpenAI keys.
	{"Anthropic API key", mustCompilePrefiltered(`^sk-ant-[A-Za-z0-9_-]{20,}$`)},
	{"OpenRouter API key", mustCompilePrefiltered(`^sk-or-v1-[A-Za-z0-9]{20,}$`)},
	// Modern OpenAI keys embed the fixed watermark T3BlbkFJ (base64 of "OpenAI")
	// between two random segments. Requiring it cuts false positives from
	// arbitrary sk-… strings and avoids mislabelling other vendors' keys.
	{"OpenAI project API key", mustCompilePrefiltered(`^sk-proj-[A-Za-z0-9_-]{8,}T3BlbkFJ[A-Za-z0-9_-]{8,}$`)},
	{"OpenAI service/admin API key", mustCompilePrefiltered(`^sk-(?:svcacct|admin|service)-[A-Za-z0-9_-]{8,}T3BlbkFJ[A-Za-z0-9_-]{8,}$`)},
	{"OpenAI API key", mustCompilePrefiltered(`^sk-[A-Za-z0-9]{8,}T3BlbkFJ[A-Za-z0-9]{8,}$`)},
	{"OpenAI realtime client secret", mustCompilePrefiltered(`^ek_[0-9a-f]{32,}$`)},
	{"PyPI upload token", mustCompilePrefiltered(`^pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}$`)},
	{"npm access token", mustCompilePrefiltered(`^npm_[A-Za-z0-9]{36}$`)},
	// sk_ secret, rk_ restricted, and sk_org_ organization keys.
	{"Stripe secret key", mustCompilePrefiltered(`^(?:[rs]k_(?:test|live|prod)|sk_org)_[A-Za-z0-9]{24,}$`)},
	{"HuggingFace token", mustCompilePrefiltered(`^hf_[A-Za-z0-9]{34,40}$`)},
	{"HuggingFace organization token", mustCompilePrefiltered(`^api_org_[A-Za-z]{34}$`)},
	{"GCP service account key", mustCompilePrefiltered(`"type":\s*"service_account"`)},
	{"Databricks token", mustCompilePrefiltered(`^dapi[a-h0-9]{32}$`)},
	{"Doppler token", mustCompilePrefiltered(`^dp\.pt\.[A-Za-z0-9]{43}$`)},
	{"SendGrid API key", mustCompilePrefiltered(`^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$`)},
	{"PlanetScale token", mustCompilePrefiltered(`^pscale_(?:pw|tkn)_[A-Za-z0-9_.-]{32,}$`)},
	{"PlanetScale OAuth token", mustCompilePrefiltered(`^pscale_oauth_[A-Za-z0-9_.=-]{32,64}$`)},
	{"Postman API key", mustCompilePrefiltered(`^PMAK-[a-f0-9]{24}-[a-f0-9]{34}$`)},
	{"RubyGems API key", mustCompilePrefiltered(`^rubygems_[a-f0-9]{48}$`)},
	{"New Relic API key", mustCompilePrefiltered(`^NRAK-[A-Z0-9]{27}$`)},
	{"Shopify access token", mustCompilePrefiltered(`^shp(?:ss|at|ca|pa)_[a-fA-F0-9]{32}$`)},
	{"Brevo (Sendinblue) API key", mustCompilePrefiltered(`^xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}$`)},
	{"age secret key", mustCompilePrefiltered(`^AGE-SECRET-KEY-1[0-9A-Z]{50,}$`)},
	{"Clojars deploy token", mustCompilePrefiltered(`^CLOJARS_[a-z0-9]{60}$`)},
	{"Dynatrace token", mustCompilePrefiltered(`^dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}$`)},
	{"Duffel API token", mustCompilePrefiltered(`^duffel_(?:test|live)_[A-Za-z0-9_-]{40,}$`)},
	{"Frame.io token", mustCompilePrefiltered(`^fio-u-[A-Za-z0-9_-]{64}$`)},
	{"Terraform Cloud token", mustCompilePrefiltered(`[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}`)},
	{"Linear API key", mustCompilePrefiltered(`^lin_api_[A-Za-z0-9]{40}$`)},
	{"New Relic browser key", mustCompilePrefiltered(`^NRJS-[a-f0-9]{19}$`)},
	{"Pulumi access token", mustCompilePrefiltered(`^pul-[a-f0-9]{40}$`)},
	{"Shippo API token", mustCompilePrefiltered(`^shippo_(?:live|test)_[a-f0-9]{40}$`)},
	// Incoming webhooks under /services/, and workflow and trigger webhooks
	// of Slack's Workflow Builder.
	{"Slack webhook URL", mustCompilePrefiltered(`^https://hooks\.slack\.com/(?:services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]{20,}|(?:workflows|triggers)/T[A-Za-z0-9_]+/(?:[A-Za-z0-9_]+/)+[A-Za-z0-9_]{20,})$`)},
	{"Alibaba access key ID", mustCompilePrefiltered(`^LTAI[A-Za-z0-9]{20}$`)},
	{"Private Packagist token", mustCompilePrefiltered(`^packagist_[a-z]{3}_[a-f0-9]{68}$`)},
	{"Adobe client secret", mustCompilePrefiltered(`^p8e-[a-z0-9]{32}$`)},
	{"Flutterwave secret key", mustCompilePrefiltered(`^FLW(?:PUBK|SECK)_TEST-[a-h0-9]{32}-X$`)},
	// cfut_ (user) and cfat_ (account) tokens end in an 8-hex checksum.
	{"Cloudflare API token", mustCompilePrefiltered(`^cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}$`)},
	{"Cloudflare Origin CA key", mustCompilePrefiltered(`^v1\.0-[a-f0-9]{24}-[a-f0-9]{146}$`)},
	{"Bitbucket Data Center token", mustCompilePrefiltered(`^BBDC-[A-Za-z0-9+/=]{32,}$`)},
	// base32 after the oy2 prefix; the 4th, 20th and last characters carry
	// fixed bits, which keeps random lowercase strings from matching.
	{"NuGet API key", mustCompilePrefiltered(`(?i)^oy2[a-p][a-z2-7]{15}[aq][a-z2-7]{25}[aeimquy4]$`)},
	// squ_ user, sqp_ project analysis and sqa_ global analysis tokens.
	{"SonarQube token", mustCompilePrefiltered(`^sq[apu]_[0-9a-f]{40}$`)},
	// Tailscale keys: tskey-<kind>-k<4-16 alnum>CNTRL-<28-40 alnum>.
	{"Tailscale auth key", mustCompilePrefiltered(`^tskey-auth-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40}$`)},
	{"Tailscale API key", mustCompilePrefiltered(`^tskey-api-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40}$`)},
	{"Tailscale OAuth client secret", mustCompilePrefiltered(`^tskey-client-k[A-Za-z0-9]{4,16}CNTRL-[A-Za-z0-9]{28,40}$`)},
	// Infisical service token: st.<uuid>.<32 hex>, with an optional second
	// 32 hex segment after rotation.
	{"Infisical service token", mustCompilePrefiltered(`^st\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[0-9a-f]{32}(\.[0-9a-f]{32})?$`)},
	// do_v1_ personal access, doo_v1_ OAuth and dor_v1_ refresh tokens.
	{"DigitalOcean token", mustCompilePrefiltered(`^do[opr]_v1_[a-f0-9]{64}$`)},
	{"HashiCorp Vault service token", mustCompilePrefiltered(`^hvs\.[A-Za-z0-9_-]{90,120}$`)},
	{"HashiCorp Vault batch token", mustCompilePrefiltered(`^hvb\.[A-Za-z0-9_-]{138,300}$`)},
	{"JFrog API key", mustCompilePrefiltered(`^AKCp[A-Za-z0-9]{69}$`)},
	// A reference token is base64 starting with "ref".
	{"JFrog reference token", mustCompilePrefiltered(`^cmVmd[A-Za-z0-9]{59}$`)},
	{"Heroku API key", mustCompilePrefiltered(`^HRKU-AA[0-9A-Za-z_-]{58}$`)},
	{"Fly.io token", mustCompilePrefiltered(`^fo1_[A-Za-z0-9_-]{43}$`)},
	// flyctl prints macaroon tokens as "FlyV1 fm2_…", several joined by commas.
	{"Fly.io macaroon token", mustCompilePrefiltered(`^(?:FlyV1 )?fm2_[A-Za-z0-9+/]{100,}={0,3}(?:,fm2_[A-Za-z0-9+/]+={0,3})*$`)},
	{"Grafana Cloud token", mustCompilePrefiltered(`^glc_[A-Za-z0-9+/]{32,400}={0,3}$`)},
	{"Grafana service account token", mustCompilePrefiltered(`^glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}$`)},
	// The legacy API key is base64 JSON starting with {"k":".
	{"Grafana API key", mustCompilePrefiltered(`^eyJrIjoi[A-Za-z0-9]{70,400}={0,3}$`)},
	{"Sentry user token", mustCompilePrefiltered(`^sntryu_[a-f0-9]{64}$`)},
	{"Sentry organization token", mustCompilePrefiltered(`^sntrys_eyJpYXQiO[A-Za-z0-9+/=_-]{50,}$`)},
	{"1Password service account token", mustCompilePrefiltered(`^ops_eyJ[A-Za-z0-9+/]{250,}={0,3}$`)},
	{"OpenShift user token", mustCompilePrefiltered(`^sha256~[A-Za-z0-9_-]{43}$`)},
	{"AWS Bedrock API key", mustCompilePrefiltered(`^ABSK[A-Za-z0-9+/]{109,269}={0,2}$`)},
	{"Notion integration token", mustCompilePrefiltered(`^ntn_[0-9]{11}[A-Za-z0-9]{35}$`)},
	{"Perplexity API key", mustCompilePrefiltered(`^pplx-[A-Za-z0-9]{48}$`)},
	{"Prefect API key", mustCompilePrefiltered(`^pnu_[A-Za-z0-9]{36}$`)},
	{"ReadMe API key", mustCompilePrefiltered(`^rdme_[a-z0-9]{70}$`)},
	{"Infracost API key", mustCompilePrefiltered(`^ico-[A-Za-z0-9]{32}$`)},
	{"Scalingo API token", mustCompilePrefiltered(`^tk-us-[A-Za-z0-9_-]{48}$`)},
	{"Sourcegraph access token", mustCompilePrefiltered(`^sgp_(?:[a-f0-9]{16}|local)_[a-f0-9]{40}$`)},
	{"Microsoft Teams webhook URL", mustCompilePrefiltered(`^https://[a-z0-9-]+\.webhook\.office\.com/webhookb2/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/IncomingWebhook/[0-9a-f]{32}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/[A-Za-z0-9_-]+)?$`)},
	// Mapbox secret access token (sk.); public tokens (pk.) are intentionally
	// excluded because they are published in client-side code.
	{"Mapbox secret access token", mustCompilePrefiltered(`^sk\.eyJ1Ijoi[A-Za-z0-9_-]{15,300}\.[A-Za-z0-9_-]{21}[AQgw]$`)},
	// Harness platform API key: pat.<account>.<id>.<token> or sat.<...>.
	{"Harness API key", mustCompilePrefiltered(`^(?:pat|sat)\.[A-Za-z0-9_-]{22}\.[0-9a-f]{24}\.[A-Za-z0-9]{20}$`)},
	// Atlassian API token (Jira/Confluence/Bitbucket Cloud).
	{"Atlassian API token", mustCompilePrefiltered(`^ATATT3[A-Za-z0-9_=\-]{180,}$`)},
}

func (r *gl006) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		for _, f := range checkVariablesNode(vars, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})
	eachServiceVariables(doc, func(vars *yaml.Node, job string) {
		for _, f := range checkVariablesNode(vars, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})

	return findings
}

// eachServiceVariables calls fn for the variables: of each services: entry at
// the top level, in default: and in every job (empty job for the first two).
func eachServiceVariables(doc *yaml.Node, fn func(vars *yaml.Node, job string)) {
	scan := func(container *yaml.Node, job string) {
		services := parser.FindKey(container, "services")
		if services == nil || services.Kind != yaml.SequenceNode {
			return
		}
		for _, service := range services.Content {
			if service.Kind == yaml.MappingNode {
				fn(parser.FindKey(service, "variables"), job)
			}
		}
	}
	mapping := parser.Unwrap(doc)
	scan(mapping, "")
	if def := parser.FindKey(mapping, "default"); def != nil {
		scan(def, "")
	}
	parser.EachJob(doc, func(name, job *yaml.Node) { scan(job, name.Value) })
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

// TokenMatcher finds one of GL006's token formats in a longer text.
type TokenMatcher interface {
	MatchString(s string) bool
	ReplaceAllStringFunc(src string, repl func(string) string) string
	String() string
}

// tokenPatterns are GL006's token formats without their ^…$ anchors. They are
// prefiltered and compile on first use like the rule's own, so the report
// redaction neither compiles them all at start nor runs each on every
// message (#1333).
var tokenPatterns = func() []TokenMatcher {
	var out []TokenMatcher
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
		out = append(out, mustCompilePrefiltered(flags+src))
	}
	return out
}()

// TokenPatterns returns GL006's token formats without their ^…$ anchors, to
// find a token inside a longer text such as a source line or a message
// (#831). The PEM and GCP service account entries are markers next to a
// secret, not the secret itself, and are left out.
func TokenPatterns() []TokenMatcher { return tokenPatterns }
