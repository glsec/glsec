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
	// AWS key-id prefixes: long-term (AKIA), temporary STS session (ASIA), and
	// the various IAM resource-id prefixes.
	{"AWS access key", regexp.MustCompile(`(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}`)},
	{"PEM private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY`)},
	{"GitHub PAT", regexp.MustCompile(`^ghp_[A-Za-z0-9]{36,}$`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{82,}$`)},
	// Covers both the fixed-length ghs_<36+> form and the newer stateless
	// ghs_<APPID>_<JWT> form (the JWT segment adds '.' separators).
	{"GitHub App installation token", regexp.MustCompile(`^ghs_[A-Za-z0-9_.-]{36,}$`)},
	{"GitHub OAuth/user/refresh token", regexp.MustCompile(`^gh[uor]_[A-Za-z0-9]{36,}$`)},
	{"Slack token", regexp.MustCompile(`^xox[baprs]-[A-Za-z0-9-]{10,}$`)},
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
	{"Stripe secret key", regexp.MustCompile(`^sk_(?:test|live)_[A-Za-z0-9]{24,}$`)},
	{"HuggingFace token", regexp.MustCompile(`^hf_[A-Za-z0-9]{34,40}$`)},
	{"GCP service account key", regexp.MustCompile(`"type":\s*"service_account"`)},
	{"Databricks token", regexp.MustCompile(`^dapi[a-h0-9]{32}$`)},
	{"Doppler token", regexp.MustCompile(`^dp\.pt\.[a-z0-9]{43}$`)},
	{"SendGrid API key", regexp.MustCompile(`^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$`)},
	{"PlanetScale token", regexp.MustCompile(`^pscale_(?:pw|tkn)_[A-Za-z0-9_.-]{32,}$`)},
	{"Postman API key", regexp.MustCompile(`^PMAK-[a-f0-9]{24}-[a-f0-9]{34}$`)},
	{"RubyGems API key", regexp.MustCompile(`^rubygems_[a-f0-9]{48}$`)},
	{"New Relic API key", regexp.MustCompile(`^NRAK-[A-Z0-9]{27}$`)},
	{"Shopify access token", regexp.MustCompile(`^shp(?:ss|at|ca|pa)_[a-fA-F0-9]{32}$`)},
	{"Brevo (Sendinblue) API key", regexp.MustCompile(`^xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}$`)},
}

func (r *gl006) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkVariablesNode(parser.FindKey(mapping, "variables"), file)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkVariablesNode(parser.FindKey(def, "variables"), file)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range checkVariablesNode(parser.FindKey(job, "variables"), file) {
			f.Job = name.Value
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

func looksLikePlaceholder(v string) bool {
	lower := strings.ToLower(v)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
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
