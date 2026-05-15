package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl012 struct{}

var GL012 = &gl012{}

func (r *gl012) ID() string { return "GL012" }

// deployKeywords identifies stages that represent deployment or release work.
var deployKeywords = []string{
	"deploy", "release", "publish", "ship", "prod", "production", "staging",
}

// excludedStages are stages where when: always can be intentional (e.g. cleanup jobs).
var excludedStages = map[string]bool{
	"test":     true,
	"build":    true,
	"lint":     true,
	"security": true,
}

func (r *gl012) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		when := parser.FindKey(job, "when")
		if when == nil || when.Kind != yaml.ScalarNode || when.Value != "always" {
			return
		}

		stage := ""
		if s := parser.FindKey(job, "stage"); s != nil && s.Kind == yaml.ScalarNode {
			stage = s.Value
		}
		hasEnvironment := parser.FindKey(job, "environment") != nil

		if !isDeployJob(stage, hasEnvironment) {
			return
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL012",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"deploy job %q has when: always — it will run even if upstream tests or security scans failed, bypassing quality gates",
				name.Value,
			),
			File: file,
			Line: when.Line,
			Col:  when.Column,
		})
	})

	return findings
}

// isDeployJob returns true if the job is a deployment context based on its
// stage name or the presence of an environment: key.
func isDeployJob(stage string, hasEnvironment bool) bool {
	// environment: is unambiguous — always a deploy job.
	if hasEnvironment {
		return true
	}
	lower := strings.ToLower(stage)
	// Exclude stages where when: always is sometimes intentional.
	if excludedStages[lower] {
		return false
	}
	for _, kw := range deployKeywords {
		if lower == kw || strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
