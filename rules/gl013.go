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

// prodTiers are environment:deployment_tier values treated as production-like,
// matching the name-keyword semantics (which also include staging).
var prodTiers = []string{"production", "staging"}

func (r *gl013) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		envNode := parser.FindKey(job, "environment")
		if envNode == nil {
			return
		}
		envName := extractEnvName(envNode)
		tier := extractDeploymentTier(envNode)
		byName := envName != "" && isProdEnv(envName)
		byTier := isProdTier(tier)
		if !byName && !byTier {
			return
		}
		if hasExecutionRestriction(job) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL013",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  gl013Message(name.Value, envName, tier, byName),
			File:     file,
			Line:     envNode.Line,
			Col:      envNode.Column,
		})
	})

	return findings
}

// gl013Message preserves the original name-based wording and adds a
// deployment_tier-based variant when the job is only flagged via its tier.
func gl013Message(job, envName, tier string, byName bool) string {
	if byName {
		return fmt.Sprintf(
			"job %q deploys to %q but has no rules: or only: clause — any branch can trigger this deployment",
			job, envName,
		)
	}
	if envName != "" {
		return fmt.Sprintf(
			"job %q deploys to %q (deployment_tier: %s) but has no rules: or only: clause — any branch can trigger this deployment",
			job, envName, tier,
		)
	}
	return fmt.Sprintf(
		"job %q has deployment_tier: %s but no rules: or only: clause — any branch can trigger this deployment",
		job, tier,
	)
}

func extractDeploymentTier(node *yaml.Node) string {
	if node.Kind != yaml.MappingNode {
		return ""
	}
	if v := parser.FindKey(node, "deployment_tier"); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

func isProdTier(tier string) bool {
	lower := strings.ToLower(tier)
	for _, t := range prodTiers {
		if lower == t {
			return true
		}
	}
	return false
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
