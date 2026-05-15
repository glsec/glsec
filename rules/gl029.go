package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl029 struct{}

var GL029 = &gl029{}

func (r *gl029) ID() string { return "GL029" }

// dockerLoginPasswordRe matches "docker login" with the short -p flag (not --password-stdin).
var dockerLoginPasswordRe = regexp.MustCompile(`\bdocker\s+login\b.*\s-p\s`)

func (r *gl029) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkDockerLoginPassword(node, file, "")...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkDockerLoginPassword(node, file, "")...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				findings = append(findings, checkDockerLoginPassword(node, file, name.Value)...)
			}
		}
	})

	return findings
}

func checkDockerLoginPassword(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if dockerLoginPasswordRe.MatchString(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL029",
				Severity: finding.Warn,
				Job:      job,
				Message:  "docker login uses -p flag — password is visible in the process table; use --password-stdin instead: echo \"$PASSWORD\" | docker login --password-stdin",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}
