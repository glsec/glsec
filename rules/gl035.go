package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
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
	mapping := parser.Unwrap(doc)

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkGitCredURL(node, file, "")...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkGitCredURL(node, file, "")...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				findings = append(findings, checkGitCredURL(node, file, name.Value)...)
			}
		}
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
