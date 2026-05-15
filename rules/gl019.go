package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl019 struct{}

var GL019 = &gl019{}

func (r *gl019) ID() string { return "GL019" }

func (r *gl019) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !isSensitiveJob(job) {
			return
		}
		if parser.FindKey(job, "resource_group") != nil {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL019",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"job %q deploys or publishes but has no resource_group: — concurrent pipeline runs can cause race conditions or partial deploys",
				name.Value,
			),
			File: file,
			Line: name.Line,
			Col:  name.Column,
		})
	})

	return findings
}
