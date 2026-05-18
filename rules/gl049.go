package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl049 struct{}

var GL049 = &gl049{}

func (r *gl049) ID() string { return "GL049" }

func (r *gl049) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !IsDeployLikeJob(name.Value, job) {
			return
		}
		interruptible := parser.FindKey(job, "interruptible")
		if interruptible == nil || interruptible.Kind != yaml.ScalarNode {
			return
		}
		if strings.ToLower(interruptible.Value) != "true" {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL049",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"deploy job %q has interruptible: true — a mid-run cancellation leaves the target environment in an undefined state; set interruptible: false or omit it (default is false)",
				name.Value,
			),
			File: file,
			Line: interruptible.Line,
			Col:  interruptible.Column,
		})
	})

	return findings
}
