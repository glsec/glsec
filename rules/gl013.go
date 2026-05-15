package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl013 struct{}

var GL013 = &gl013{}

func (r *gl013) ID() string { return "GL013" }

// prodKeywords identifies environment names that represent production-like targets.
var prodKeywords = []string{
	"production", "prod", "live", "staging",
}

func (r *gl013) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		envNode := parser.FindKey(job, "environment")
		if envNode == nil {
			return
		}
		envName := extractEnvName(envNode)
		if envName == "" || !isProdEnv(envName) {
			return
		}
		if hasExecutionRestriction(job) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL013",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"job %q deploys to %q but has no rules: or only: clause — any branch can trigger this deployment",
				name.Value, envName,
			),
			File: file,
			Line: envNode.Line,
			Col:  envNode.Column,
		})
	})

	return findings
}

func extractEnvName(node *yaml.Node) string {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value
	case yaml.MappingNode:
		if v := parser.FindKey(node, "name"); v != nil && v.Kind == yaml.ScalarNode {
			return v.Value
		}
	}
	return ""
}

func isProdEnv(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range prodKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// hasExecutionRestriction returns true if the job has a rules: or only: clause
// that can limit which branches or conditions trigger it.
func hasExecutionRestriction(job *yaml.Node) bool {
	return parser.FindKey(job, "rules") != nil || parser.FindKey(job, "only") != nil
}
