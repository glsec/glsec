package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl036 struct{}

var GL036 = &gl036{}

func (r *gl036) ID() string { return "GL036" }

// connStringRe matches a URL with embedded userinfo where the password does not start with $.
// Handles both "user:pass@" and ":pass@" (empty username, common in Redis URLs).
var connStringRe = regexp.MustCompile(
	`[a-zA-Z][a-zA-Z0-9+\-.]*://[^\s@/]*:[^$\s@/][^\s@/]*@`,
)

func (r *gl036) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkConnStringVars(parser.FindKey(mapping, "variables"), file, "")...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkConnStringVars(parser.FindKey(def, "variables"), file, "")...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		findings = append(findings, checkConnStringVars(parser.FindKey(job, "variables"), file, name.Value)...)
	})

	return findings
}

func checkConnStringVars(node *yaml.Node, file, job string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]

		scalar := resolveScalar(valNode)
		if scalar == nil {
			continue
		}
		if !connStringRe.MatchString(scalar.Value) {
			continue
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL036",
			Severity: finding.Warn,
			Job:      job,
			Message: fmt.Sprintf(
				"variable %q contains a connection string with embedded credentials — store the password in a masked CI variable and reference it: e.g. scheme://user:${PASSWORD}@host",
				keyNode.Value,
			),
			File: file,
			Line: keyNode.Line,
			Col:  keyNode.Column,
		})
	}
	return findings
}
