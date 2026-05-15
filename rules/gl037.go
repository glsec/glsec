package rules

import (
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl037 struct{}

var GL037 = &gl037{}

func (r *gl037) ID() string { return "GL037" }

func (r *gl037) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)

	// Only flag when top-level variables: has at least one secret-like name.
	if !topLevelHasSecretVars(parser.FindKey(mapping, "variables")) {
		return nil
	}

	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if parser.FindKey(job, "trigger") == nil {
			return
		}
		if inheritVarsFalse(parser.FindKey(job, "inherit")) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL037",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "trigger: job has no inherit: variables: false — top-level secret variables are implicitly forwarded to the downstream pipeline; add inherit: variables: false and pass only what the downstream needs",
			File:     file,
			Line:     name.Line,
			Col:      name.Column,
		})
	})
	return findings
}

// topLevelHasSecretVars returns true when any variable key in the node has a secret-like suffix.
func topLevelHasSecretVars(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if hasSecretSuffix(node.Content[i].Value) {
			return true
		}
	}
	return false
}

// inheritVarsFalse returns true when the inherit: block explicitly sets variables: false.
func inheritVarsFalse(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	v := parser.FindKey(node, "variables")
	return v != nil && v.Value == "false"
}
