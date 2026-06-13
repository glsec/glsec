package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl035 struct{}

var GL035 = &gl035{}

func (r *gl035) ID() string { return "GL035" }

// gitCredURLRe matches a git command followed by a URL with embedded userinfo credentials.
var gitCredURLRe = regexp.MustCompile(
	`\bgit\s+(?:clone|push|fetch|pull|remote\s+\S+)\b.*https?://[^\s@]+:[^\s@]+@`,
)

func (r *gl035) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkGitCredURL(node, file, job)...)
	})
	return findings
}

func checkGitCredURL(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if gitCredURLRe.MatchString(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL035",
				Severity: finding.Warn,
				Job:      job,
				Message:  "git command uses URL with embedded credentials (user:token@host) — the credential sits in the runner's process table and in .git/config, and reaches the job log if CI_DEBUG_TRACE is enabled or the tool does not redact it (git redacts its own output, many tools do not); use a credential helper, an auth header, or an SSH remote instead of embedding it in the URL",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}
