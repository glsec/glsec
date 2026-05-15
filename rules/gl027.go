package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl027 struct{}

var GL027 = &gl027{}

func (r *gl027) ID() string { return "GL027" }

func (r *gl027) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkMaskedVariables(parser.FindKey(mapping, "variables"), file, "")...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkMaskedVariables(parser.FindKey(def, "variables"), file, "")...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range checkMaskedVariables(parser.FindKey(job, "variables"), file, name.Value) {
			findings = append(findings, f)
		}
	})

	return findings
}

func checkMaskedVariables(node *yaml.Node, file, job string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		varName := node.Content[i].Value
		val := node.Content[i+1]

		// Only flag the long-form mapping — scalar form cannot carry masked: true.
		if val.Kind != yaml.MappingNode {
			continue
		}
		if !hasSecretSuffix(varName) {
			continue
		}

		maskedNode := parser.FindKey(val, "masked")
		if maskedNode != nil && maskedNode.Value == "true" {
			continue
		}

		f := finding.Finding{
			RuleID:   "GL027",
			Severity: finding.Warn,
			Job:      job,
			Message: fmt.Sprintf(
				"variable %q has a secret-like name but is missing \"masked: true\" — its value will appear in CI job logs",
				varName,
			),
			File: file,
			Line: node.Content[i].Line,
			Col:  node.Content[i].Column,
		}
		findings = append(findings, f)
	}
	return findings
}
