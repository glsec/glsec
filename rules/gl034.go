package rules

import (
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl034 struct{}

var GL034 = &gl034{}

func (r *gl034) ID() string { return "GL034" }

func (r *gl034) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		triggerNode := parser.FindKey(job, "trigger")
		if triggerNode == nil {
			return
		}

		// Scalar trigger (e.g. "trigger: other/project") — cannot carry strategy: depend.
		if triggerNode.Kind == yaml.ScalarNode {
			findings = append(findings, finding.Finding{
				RuleID:   "GL034",
				Severity: finding.Warn,
				Job:      name.Value,
				Message:  "trigger: job has no strategy: depend — child/downstream pipeline failures are silently ignored; add strategy: depend to mirror the child pipeline status",
				File:     file,
				Line:     triggerNode.Line,
				Col:      triggerNode.Column,
			})
			return
		}

		if triggerNode.Kind != yaml.MappingNode {
			return
		}

		strategyNode := parser.FindKey(triggerNode, "strategy")
		if strategyNode != nil && strategyNode.Value == "depend" {
			return
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL034",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "trigger: job has no strategy: depend — child/downstream pipeline failures are silently ignored; add strategy: depend to mirror the child pipeline status",
			File:     file,
			Line:     triggerNode.Line,
			Col:      triggerNode.Column,
		})
	})

	return findings
}
