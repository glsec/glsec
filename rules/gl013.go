// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl013 struct{}

var GL013 = &gl013{}

func (r *gl013) ID() string { return "GL013" }

// prodTiers are environment:deployment_tier values treated as production-like,
// matching the name-keyword semantics (which also include staging).
var prodTiers = []string{"production", "staging"}

// CheckDocument reads the file in its pipeline context (#1502): a child
// pipeline or included file that only protected refs reach has no job that
// runs on an unprotected branch, and in a child pipeline started on any ref,
// if: $CI_PIPELINE_SOURCE == "parent_pipeline" restricts nothing.
func (r *gl013) CheckDocument(doc *parser.Document, file string) []finding.Finding {
	ctx := contextOf(doc)
	if ctx.protected {
		return nil
	}
	return r.check(doc.Root, file, ctx)
}

func (r *gl013) Check(doc *yaml.Node, file string) []finding.Finding {
	return r.check(doc, file, docContext{})
}

func (r *gl013) check(doc *yaml.Node, file string, ctx docContext) []finding.Finding {
	// A workflow that only runs on protected refs keeps every branch out.
	scope := ctx.scope(parser.Unwrap(doc))
	if scope.protectedOnly {
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
		// Rules that let some entry run the job on any ref are no branch
		// restriction either (#1486).
		var open *yaml.Node
		var openWhy string
		if !mrOnly && (in.Key(job, "rules") != nil || in.Key(job, "only") != nil) {
			if in.Key(job, "only") != nil || in.Key(job, "except") != nil {
				return
			}
			if open, openWhy = scope.openEntry(in.Key(job, "rules")); open == nil {
				return
			}
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
		if open != nil {
			// As for MR-only deploys, staging is often a preview per branch.
			if isProductionOnly(envName, tier) && deploysToEnvironment(envNode) {
				findings = append(findings, finding.Finding{
					RuleID:   "GL013",
					Severity: finding.Warn,
					Job:      name.Value,
					Message:  gl013OpenRuleMessage(name.Value, envName, tier, openWhy),
					File:     file,
					Line:     open.Line,
					Col:      open.Column,
				})
			}
			return
		}
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
		return !parser.IsFalse(p)
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

func gl013OpenRuleMessage(job, envName, tier, why string) string {
	target := fmt.Sprintf("%q", envName)
	if envName == "" {
		target = "deployment_tier: " + tier
	}
	return fmt.Sprintf(
		"job %q deploys to %s, but its rules: entry %s — any branch can run this deployment; restrict every rules: entry that runs the job to the protected branch ($CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH) or to tags, or exclude unprotected refs first (- if: $CI_COMMIT_REF_PROTECTED != \"true\" with when: never)",
		job, target, why,
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
	return !hasNameWord(envName, "staging") && productionName(envName, false)
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
	return hasNameWord(name, "staging") || productionName(name, true)
}

// nameWords splits a name into its letter and digit runs, so prod1 and
// staging2 still contain prod and staging.
func nameWords(name string) []string {
	var words []string
	var cur []rune
	for _, r := range strings.ToLower(name) {
		letter, digit := unicode.IsLetter(r), unicode.IsDigit(r)
		if len(cur) > 0 && (!letter && !digit || unicode.IsDigit(cur[len(cur)-1]) != digit) {
			words = append(words, string(cur))
			cur = cur[:0]
		}
		if letter || digit {
			cur = append(cur, r)
		}
	}
	if len(cur) > 0 {
		words = append(words, string(cur))
	}
	return words
}

func hasNameWord(name, word string) bool {
	for _, part := range nameWords(name) {
		if part == word {
			return true
		}
	}
	return false
}

// productionName matches whole name components. Pre-production counts for
// environment classification but not as an MR-only production deployment.
func productionName(name string, includePre bool) bool {
	words := nameWords(name)
	for i, word := range words {
		if includePre && (word == "preprod" || word == "preproduction") {
			return true
		}
		if word != "prod" && word != "production" && word != "live" {
			continue
		}
		if i > 0 && (words[i-1] == "non" || (!includePre && words[i-1] == "pre")) {
			continue
		}
		return true
	}
	return false
}

// hasExecutionRestriction returns true if the job has a rules: or only: clause
// that can limit which branches or conditions trigger it.
func hasExecutionRestriction(job *yaml.Node) bool {
	return parser.FindKey(job, "rules") != nil || parser.FindKey(job, "only") != nil
}
