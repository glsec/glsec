// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl034 struct{}

var GL034 = &gl034{}

func (r *gl034) ID() string { return "GL034" }

const gl034Message = "trigger: job has no strategy: — child/downstream pipeline failures are silently ignored; add strategy: mirror (strategy: depend before GitLab 18.2) to reflect the downstream pipeline status"

func (r *gl034) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !runsInheritedJob(in, name, job) {
			return
		}
		triggers := in.Chain(job, "trigger")
		if len(triggers) == 0 {
			return
		}
		triggerNode := triggers[0]

		// Scalar trigger (e.g. "trigger: other/project") — cannot carry a strategy.
		if triggerNode.Kind == yaml.ScalarNode {
			findings = append(findings, finding.Finding{
				RuleID:   "GL034",
				Severity: finding.Warn,
				Job:      name.Value,
				Message:  gl034Message,
				File:     file,
				Line:     triggerNode.Line,
				Col:      triggerNode.Column,
			})
			return
		}

		if triggerNode.Kind != yaml.MappingNode {
			return
		}

		// trigger: is deep-merged along extends:, so the strategy can come from
		// a template. mirror (GitLab 18.2+) and the older depend both wait for
		// the downstream status.
		for _, t := range triggers {
			if t.Kind != yaml.MappingNode {
				break
			}
			if s := parser.FindKey(t, "strategy"); s != nil {
				if s.Value == "mirror" || s.Value == "depend" {
					return
				}
				break
			}
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL034",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  gl034Message,
			File:     file,
			Line:     triggerNode.Line,
			Col:      triggerNode.Column,
		})
	})

	return findings
}
