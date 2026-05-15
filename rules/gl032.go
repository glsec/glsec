package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl032 struct{}

var GL032 = &gl032{}

func (r *gl032) ID() string { return "GL032" }

// sshKeyEchoRe matches echo/printf piping or redirecting to an SSH key file path,
// or echoing a variable with a key-like name to any destination.
var sshKeyEchoRe = regexp.MustCompile(
	`\b(?:echo|printf)\b` +
		`.*` +
		`(?:` +
		// redirect or pipe to ssh key file
		`[|>].*\.ssh/` +
		`|` +
		// variable name contains KEY or PRIVATE
		`\$(?:\{[A-Za-z_]*(?:PRIVATE|_KEY)[A-Za-z_]*\}|[A-Za-z_]*(?:PRIVATE|_KEY)[A-Za-z_]*)` +
		`)`,
)

func (r *gl032) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkSSHKeyEcho(node, file, "")...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkSSHKeyEcho(node, file, "")...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				findings = append(findings, checkSSHKeyEcho(node, file, name.Value)...)
			}
		}
	})

	return findings
}

func checkSSHKeyEcho(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if sshKeyEchoRe.MatchString(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL032",
				Severity: finding.Warn,
				Job:      job,
				Message:  "SSH private key written to file via echo — key value appears in job logs when debug tracing is active; use ssh-add with stdin instead: echo \"$KEY\" | ssh-add -",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}
