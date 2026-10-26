// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl039 struct{}

var GL039 = &gl039{}

func (r *gl039) ID() string { return "GL039" }

// silencedRe matches "|| true", "|| exit 0" or "|| :" at end of a pipeline
// segment.
var silencedRe = regexp.MustCompile(`\|\|\s*(?:(?:true|exit\s+0)\b|:(?:[\s;)]|$))`)

// scannerCmd builds the pattern for a scanner that has to be in command
// position, so an install step (pip install pip-audit) doesn't count: at the
// start of a command, after a runner (npx, pipx run, poetry run, uv run, bundle
// exec, python -m, go run, exec, sudo), behind a path or module path, and after
// leading VAR=value assignments.
func scannerCmd(cmd string) *regexp.Regexp {
	return regexp.MustCompile(`(?:^|[;&|(]|\$\()\s*(?:\w+=\S*\s+)*` +
		`(?:(?:npx|bunx)\s+(?:-y\s+|--yes\s+)?|pipx\s+run\s+|(?:poetry|pipenv|uv)\s+run\s+|bundle\s+exec\s+|python[0-9.]*\s+-m\s+|go\s+run\s+|exec\s+|sudo\s+)?` +
		`(?:[\w.@/-]*/)?(?:` + cmd + `)(?:[\s@;|&)]|$)`)
}

type auditTool struct {
	name string
	re   *regexp.Regexp
}

var auditTools = []auditTool{
	{name: "npm audit", re: regexp.MustCompile(`\b(?:npm|pnpm|yarn)\s+audit\b`)},
	{name: "composer audit", re: regexp.MustCompile(`\bcomposer\s+audit\b`)},
	{name: "trivy", re: regexp.MustCompile(`\btrivy\b`)},
	{name: "grype", re: regexp.MustCompile(`\bgrype\b`)},
	{name: "snyk", re: regexp.MustCompile(`\bsnyk\b`)},
	{name: "osv-scanner", re: regexp.MustCompile(`\bosv-scanner\b`)},
	{name: "retire", re: regexp.MustCompile(`\bretire\b`)},
	{name: "safety check", re: regexp.MustCompile(`\bsafety\s+(?:check|scan)\b`)},
	{name: "anchore-cli", re: regexp.MustCompile(`\banchore-cli\b`)},
	{name: "inspector check", re: regexp.MustCompile(`\binspector\s+check\b`)},
	{name: "syft", re: regexp.MustCompile(`\bsyft\b`)},
	// Secret scanners.
	{name: "gitleaks", re: scannerCmd(`gitleaks`)},
	{name: "trufflehog", re: scannerCmd(`trufflehog`)},
	{name: "ggshield", re: scannerCmd(`ggshield`)},
	{name: "detect-secrets", re: scannerCmd(`detect-secrets(?:-hook)?`)},
	// SAST.
	{name: "semgrep", re: scannerCmd(`semgrep`)},
	{name: "gosec", re: scannerCmd(`gosec`)},
	{name: "bandit", re: scannerCmd(`bandit`)},
	{name: "brakeman", re: scannerCmd(`brakeman`)},
	// IaC.
	{name: "checkov", re: scannerCmd(`checkov`)},
	{name: "tfsec", re: scannerCmd(`tfsec`)},
	{name: "kics", re: scannerCmd(`kics`)},
	{name: "terrascan", re: scannerCmd(`terrascan`)},
	{name: "kubescape", re: scannerCmd(`kubescape`)},
	// Dependencies.
	{name: "govulncheck", re: scannerCmd(`govulncheck`)},
	{name: "pip-audit", re: scannerCmd(`pip-audit|pip_audit`)},
	{name: "dependency-check", re: scannerCmd(`dependency-check(?:\.sh|\.bat)?`)},
	{name: "cargo audit", re: scannerCmd(`cargo\s+audit`)},
	{name: "cargo deny", re: scannerCmd(`cargo\s+deny`)},
	{name: "bundle-audit", re: scannerCmd(`bundle-audit|bundler-audit|bundle\s+audit`)},
}

func (r *gl039) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkAuditSilenced(node, file, job)...)
	})
	return findings
}

func checkAuditSilenced(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		silencer := silencedRe.FindString(item.Value)
		if silencer == "" {
			continue
		}
		silencer = strings.Join(strings.Fields(strings.TrimRight(silencer, ";)")), " ")
		for _, tool := range auditTools {
			if tool.re.MatchString(item.Value) {
				findings = append(findings, finding.Finding{
					RuleID:   "GL039",
					Severity: finding.Warn,
					Job:      job,
					Message: fmt.Sprintf(
						"security check %q silenced with %q — failures are discarded; use allow_failure: true at job level to keep the signal visible in the pipeline UI",
						tool.name, silencer,
					),
					File: file,
					Line: item.Line,
					Col:  item.Column,
				})
				break
			}
		}
	}
	return findings
}
