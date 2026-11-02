// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
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
	// A workflow that only runs on protected refs keeps every branch out.
	if workflowRestrictsToProtected(parser.Unwrap(doc)) {
		return nil
	}

	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// Hidden jobs are templates GitLab never runs; the jobs extending them
		// are checked with what they inherit.
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		// A job that runs only in merge request pipelines deploys the MR's
		// source commit before it is merged, so its rules are no branch
		// restriction (#1135).
		mrOnly := runsOnlyInMRPipelines(in, job)
		if !mrOnly && (in.Key(job, "rules") != nil || in.Key(job, "only") != nil) {
			return
		}
		// A base in another file, or the included job this one overrides,
		// may carry the guard.
		if !in.ExtendsResolved(job) || in.IncludedOverride(job) {
			return
		}
		line, col := name.Line, name.Column
		envNode := in.Key(job, "environment")
		if own := parser.FindKey(job, "environment"); own != nil {
			line, col = own.Line, own.Column
		}
		var envName, tier string
		if envNode != nil {
			envName = extractEnvName(envNode)
			tier = extractDeploymentTier(envNode)
		}
		byName := envName != "" && isProdEnv(envName)
		if mrOnly {
			// Staging often is a preview per MR; only production counts.
			if isProductionOnly(envName, tier) && deploysToEnvironment(envNode) {
				findings = append(findings, finding.Finding{
					RuleID:   "GL013",
					Severity: finding.Warn,
					Job:      name.Value,
					Message:  gl013MRMessage(name.Value, envName, tier),
					File:     file,
					Line:     line,
					Col:      col,
				})
			}
			return
		}
		if byName || isProdTier(tier) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL013",
				Severity: finding.Warn,
				Job:      name.Value,
				Message:  gl013Message(name.Value, envName, tier, byName),
				File:     file,
				Line:     line,
				Col:      col,
			})
			return
		}
		if publishesMainPages(name.Value, in.Key(job, "pages")) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL013",
				Severity: finding.Warn,
				Job:      name.Value,
				Message: fmt.Sprintf(
					"job %q publishes the project's GitLab Pages site but has no rules: or only: clause — any branch can replace the live site",
					name.Value,
				),
				File: file,
				Line: name.Line,
				Col:  name.Column,
			})
		}
	})

	return findings
}

// publishesMainPages reports whether a job deploys GitLab Pages to the main
// site, given its pages: value: a job named pages or one with a pages: key,
// unless pages: is false or sets a path_prefix (a parallel deployment beside
// the main site). The most recent Pages job wins, whatever its branch, so an
// unguarded one lets any pushed branch replace the live site.
func publishesMainPages(jobName string, p *yaml.Node) bool {
	if p == nil {
		return jobName == "pages"
	}
	switch p.Kind {
	case yaml.ScalarNode:
		return p.Value != "false"
	case yaml.MappingNode:
		prefix := parser.FindKey(p, "path_prefix")
		return prefix == nil || (prefix.Kind == yaml.ScalarNode && prefix.Value == "")
	}
	return false
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

func gl013MRMessage(job, envName, tier string) string {
	target := fmt.Sprintf("%q", envName)
	if envName == "" {
		target = "deployment_tier: " + tier
	}
	return fmt.Sprintf(
		"job %q deploys to %s but runs only in merge request pipelines — they build the MR's source commit before anyone merged it; restrict the job to the protected branch ($CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH) or to tags",
		job, target,
	)
}

// isProductionOnly reports a production environment by name (production,
// prod, live) or by deployment_tier: production, leaving staging out.
func isProductionOnly(envName, tier string) bool {
	if strings.EqualFold(tier, "production") {
		return true
	}
	if tier != "" {
		return false
	}
	lower := strings.ToLower(envName)
	return !strings.Contains(lower, "staging") && (strings.Contains(lower, "prod") || strings.Contains(lower, "live"))
}

// deploysToEnvironment reports whether the environment: value deploys: an
// action of prepare, verify, access or stop changes nothing in it.
func deploysToEnvironment(env *yaml.Node) bool {
	if env == nil || env.Kind != yaml.MappingNode {
		return true
	}
	a := parser.FindKey(env, "action")
	if a == nil || a.Kind != yaml.ScalarNode {
		return true
	}
	return a.Value == "" || a.Value == "start"
}

var (
	// mrSourceRe matches an operand that requires a merge request pipeline
	// by its source, in either operand order.
	mrSourceRe = regexp.MustCompile(`^(?:\$\{?CI_PIPELINE_SOURCE\}?\s*(?:==\s*["']merge_request_event["']|=~\s*/[^/]*merge_request[^/]*/[a-z]*)|["']merge_request_event["']\s*==\s*\$\{?CI_PIPELINE_SOURCE\}?)$`)
	// mrVarRe matches an operand that tests a merge request variable for
	// presence or a value; these are only set in merge request pipelines.
	mrVarRe = regexp.MustCompile(`^(?:\$\{?CI_MERGE_REQUEST_\w+\}?(?:\s*(?:==|=~)\s*(.+))?|(["'][^"']*["'])\s*==\s*\$\{?CI_MERGE_REQUEST_\w+\}?)$`)
	// branchOrTagRe matches an operand that tests the branch or tag of a
	// branch or tag pipeline; both are unset in a merge request pipeline.
	branchOrTagRe = regexp.MustCompile(`\$\{?CI_COMMIT_(?:BRANCH|TAG)\b`)
)

// runsOnlyInMRPipelines reports whether every rule that lets the job run
// requires a merge request pipeline, or only: names merge_requests alone.
func runsOnlyInMRPipelines(in *Inheritance, job *yaml.Node) bool {
	if rules := in.Key(job, "rules"); rules != nil {
		if rules.Kind != yaml.SequenceNode {
			return false
		}
		saw := false
		for _, item := range rules.Content {
			if item.Kind != yaml.MappingNode {
				return false
			}
			if ruleExcludes(item) {
				continue
			}
			ifNode := parser.FindKey(item, "if")
			if ifNode == nil || ifNode.Kind != yaml.ScalarNode || !ifRequiresMR(ifNode.Value) {
				return false
			}
			saw = true
		}
		return saw
	}
	return onlyMergeRequests(in.Key(job, "only"))
}

// ifRequiresMR reports whether a rules:if expression is true only in a merge
// request pipeline: every || alternative requires one, and of && operands
// one does while none tests a branch or tag.
func ifRequiresMR(expr string) bool {
	expr = trimOuterParens(strings.TrimSpace(expr))
	alts := splitTopLevel(expr, "||")
	if alts == nil {
		return false
	}
	if len(alts) > 1 {
		for _, alt := range alts {
			if !ifRequiresMR(alt) {
				return false
			}
		}
		return true
	}
	ops := splitTopLevel(expr, "&&")
	if len(ops) > 1 {
		requires := false
		for _, op := range ops {
			if branchOrTagRe.MatchString(op) {
				return false
			}
			requires = requires || ifRequiresMR(op)
		}
		return requires
	}
	if mrSourceRe.MatchString(expr) {
		return true
	}
	m := mrVarRe.FindStringSubmatch(expr)
	if m == nil {
		return false
	}
	v := strings.TrimSpace(m[1] + m[2])
	return v != "null" && v != `""` && v != "''"
}

// onlyMergeRequests reports whether a legacy only: clause admits nothing but
// merge_requests.
func onlyMergeRequests(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value == "merge_requests"
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Kind != yaml.ScalarNode || c.Value != "merge_requests" {
				return false
			}
		}
		return len(n.Content) > 0
	case yaml.MappingNode:
		// variables: and changes: narrow the refs further.
		return onlyMergeRequests(parser.FindKey(n, "refs"))
	}
	return false
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
