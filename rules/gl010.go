// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl010 struct{}

var GL010 = &gl010{}

func (r *gl010) ID() string { return "GL010" }

func (r *gl010) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		trigger := parser.FindKey(job, "trigger")
		if trigger == nil || trigger.Kind != yaml.MappingNode {
			return
		}
		// A child pipeline (trigger: include:) runs in the same project and
		// has its variables already; only another project is a new audience.
		if parser.FindKey(trigger, "project") == nil {
			return
		}
		forward := parser.FindKey(trigger, "forward")
		if forward == nil || forward.Kind != yaml.MappingNode {
			return
		}
		pv := parser.FindKey(forward, "pipeline_variables")
		if pv == nil || pv.Kind != yaml.ScalarNode || pv.Value != "true" {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL010",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"trigger job %q forwards all pipeline variables to the downstream pipeline — masked variables are not re-masked and may be exposed in downstream job logs",
				name.Value,
			),
			File: file,
			Line: pv.Line,
			Col:  pv.Column,
		})
	})

	return findings
}
