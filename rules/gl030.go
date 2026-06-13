package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl030 struct{}

var GL030 = &gl030{}

func (r *gl030) ID() string { return "GL030" }

var sshKeyscanRe = regexp.MustCompile(`\bssh-keyscan\b`)

func (r *gl030) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkSSHKeyscan(node, file, job)...)
	})
	return findings
}

func checkSSHKeyscan(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if sshKeyscanRe.MatchString(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL030",
				Severity: finding.Warn,
				Job:      job,
				Message:  "ssh-keyscan trusts whatever key the remote host presents — store a pre-verified known-hosts entry in a protected CI variable instead: echo \"$SSH_KNOWN_HOSTS\" >> ~/.ssh/known_hosts",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}
