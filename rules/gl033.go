package rules

import (
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl033 struct{}

var GL033 = &gl033{}

func (r *gl033) ID() string { return "GL033" }

func (r *gl033) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	if f := checkDebugTrace(parser.FindKey(mapping, "variables"), file, ""); f != nil {
		findings = append(findings, *f)
	}

	if def := parser.FindKey(mapping, "default"); def != nil {
		if f := checkDebugTrace(parser.FindKey(def, "variables"), file, ""); f != nil {
			findings = append(findings, *f)
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if f := checkDebugTrace(parser.FindKey(job, "variables"), file, name.Value); f != nil {
			findings = append(findings, *f)
		}
	})

	return findings
}

func checkDebugTrace(node *yaml.Node, file, job string) *finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		if key.Value != "CI_DEBUG_TRACE" {
			continue
		}
		scalar := resolveScalar(val)
		if scalar == nil {
			continue
		}
		if scalar.Value != "true" {
			continue
		}
		f := finding.Finding{
			RuleID:   "GL033",
			Severity: finding.Error,
			Job:      job,
			Message:  "CI_DEBUG_TRACE: \"true\" is committed — shell tracing dumps all variable values including secrets to the job log; remove it and use the GitLab UI run-pipeline dialog for transient debugging",
			File:     file,
			Line:     key.Line,
			Col:      key.Column,
		}
		return &f
	}
	return nil
}
