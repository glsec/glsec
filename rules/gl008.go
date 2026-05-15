package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl008 struct{}

var GL008 = &gl008{}

func (r *gl008) ID() string { return "GL008" }

// securityScanJobs are the GitLab-defined job names created when security
// scan templates are included. Failing these jobs with allow_failure: true
// causes GitLab to silently skip security result ingestion.
var securityScanJobs = map[string]bool{
	"sast":                  true,
	"sast-iac":              true,
	"secret_detection":      true,
	"dast":                  true,
	"dast_api":              true,
	"container_scanning":    true,
	"dependency_scanning":   true,
	"coverage_fuzzing":      true,
	"api_fuzzing":           true,
	"license_scanning":      true,
	"license_management":    true,
}

func (r *gl008) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !securityScanJobs[name.Value] {
			return
		}
		af := parser.FindKey(job, "allow_failure")
		if af == nil {
			return
		}
		// Only flag scalar `true`; allow_failure: {exit_codes: [...]} is intentional.
		if af.Kind == yaml.ScalarNode && af.Value == "true" {
			findings = append(findings, finding.Finding{
				RuleID:   "GL008",
				Severity: finding.Warn,
				Job:      name.Value,
				Message: fmt.Sprintf(
					"security scan job %q has allow_failure: true — scan failures are silently ignored and security results may not be ingested by GitLab",
					name.Value,
				),
				File: file,
				Line: af.Line,
				Col:  af.Column,
			})
		}
	})

	return findings
}
