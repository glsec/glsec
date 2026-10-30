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

// silencedRe matches "|| true", "|| exit 0", "|| :" or "|| echo …" at end of
// a pipeline segment. An echo is a silencer only when no failing exit
// follows it (#988), which silencerAt checks.
var silencedRe = mustCompilePrefiltered(`\|\|\s*(?:(?:true|exit\s+0)\b|:(?:[\s;)]|$)|echo\b[^;&|\n]*)`)

// failingExitRe matches what makes `|| echo …` fail after all: && exit 1,
// ; exit 2.
var failingExitRe = regexp.MustCompile(`^\s*(?:&&|;)\s*exit\s+[1-9]`)

// silencerAt returns the silencer of a script item and where it starts.
func silencerAt(item string) (string, int) {
	for _, loc := range silencedRe.FindAllStringIndex(item, -1) {
		m := item[loc[0]:loc[1]]
		if strings.Contains(m, "echo") && failingExitRe.MatchString(item[loc[1]:]) {
			continue
		}
		return m, loc[0]
	}
	return "", -1
}

// scannerCmd builds the pattern for a scanner that has to be in command
// position, so an install step (pip install pip-audit) doesn't count: at the
// start of a command, after a runner (npx, pipx run, poetry run, uv run, bundle
// exec, python -m, go run, exec, sudo), behind a path or module path, and after
// leading VAR=value assignments.
func scannerCmd(cmd string) prefiltered {
	return mustCompilePrefiltered(`(?:^|[;&|(]|\$\()\s*(?:\w+=\S*\s+)*` +
		`(?:(?:npx|bunx)\s+(?:-y\s+|--yes\s+)?|pipx\s+run\s+|(?:poetry|pipenv|uv)\s+run\s+|bundle\s+exec\s+|python[0-9.]*\s+-m\s+|go\s+run\s+|exec\s+|sudo\s+)?` +
		`(?:[\w.@/-]*/)?(?:` + cmd + `)(?:[\s@;|&)]|$)`)
}

type auditTool struct {
	name string
	re   prefiltered
}

var auditTools = []auditTool{
	{name: "npm audit", re: mustCompilePrefiltered(`\b(?:npm|pnpm|yarn)\s+audit\b`)},
	{name: "composer audit", re: mustCompilePrefiltered(`\bcomposer\s+audit\b`)},
	{name: "trivy", re: mustCompilePrefiltered(`\btrivy\b`)},
	{name: "grype", re: mustCompilePrefiltered(`\bgrype\b`)},
	{name: "snyk", re: mustCompilePrefiltered(`\bsnyk\b`)},
	{name: "osv-scanner", re: mustCompilePrefiltered(`\bosv-scanner\b`)},
	{name: "retire", re: mustCompilePrefiltered(`\bretire\b`)},
	{name: "safety check", re: mustCompilePrefiltered(`\bsafety\s+(?:check|scan)\b`)},
	{name: "anchore-cli", re: mustCompilePrefiltered(`\banchore-cli\b`)},
	{name: "inspector check", re: mustCompilePrefiltered(`\binspector\s+check\b`)},
	{name: "syft", re: mustCompilePrefiltered(`\bsyft\b`)},
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
		silencer, at := silencerAt(item.Value)
		if silencer == "" {
			continue
		}
		silencer = strings.Join(strings.Fields(strings.TrimRight(silencer, ";)")), " ")
		if strings.HasPrefix(silencer, "|| echo") {
			silencer = "|| echo"
		}
		for _, tool := range auditTools {
			if tool.re.MatchString(item.Value) {
				// A report run silenced on purpose, with the same tool run
				// again without silencing to fail the job (#988).
				if gatedElsewhere(node, item, tool) {
					break
				}
				line, col := scriptMatchPos(item, at)
				findings = append(findings, finding.Finding{
					RuleID:   "GL039",
					Severity: finding.Warn,
					Job:      job,
					Message: fmt.Sprintf(
						"security check %q silenced with %q — failures are discarded; use allow_failure: true at job level to keep the signal visible in the pipeline UI",
						tool.name, silencer,
					),
					File: file,
					Line: line,
					Col:  col,
				})
				break
			}
		}
	}
	return findings
}

// gatedElsewhere reports whether another item of the same script runs tool
// without a silencer.
func gatedElsewhere(node, silenced *yaml.Node, tool auditTool) bool {
	for _, other := range node.Content {
		if other == silenced || other.Kind != yaml.ScalarNode || !tool.re.MatchString(other.Value) {
			continue
		}
		if s, _ := silencerAt(other.Value); s == "" {
			return true
		}
	}
	return false
}
