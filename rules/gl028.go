package rules

import (
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl028 struct{}

var GL028 = &gl028{}

func (r *gl028) ID() string { return "GL028" }

func (r *gl028) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		artifactsNode := parser.FindKey(job, "artifacts")
		if artifactsNode == nil || artifactsNode.Kind != yaml.MappingNode {
			return
		}

		untrackedNode := parser.FindKey(artifactsNode, "untracked")
		if untrackedNode == nil || untrackedNode.Value != "true" {
			return
		}

		// Safe if paths: is set (restricts what is uploaded).
		if pathsNode := parser.FindKey(artifactsNode, "paths"); pathsNode != nil {
			return
		}
		// Safe if exclude: is set (user has explicitly filtered sensitive patterns).
		if excludeNode := parser.FindKey(artifactsNode, "exclude"); excludeNode != nil {
			return
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL028",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "artifacts:untracked:true without paths: or exclude: — archives all untracked files including .env, *.key, and other sensitive files; restrict with paths: or add an exclude: list",
			File:     file,
			Line:     untrackedNode.Line,
			Col:      untrackedNode.Column,
		})
	})

	return findings
}
