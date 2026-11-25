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

func (r *gl013) Check(doc *yaml.Node, file string) []finding.Finding {
	// A workflow that only runs on protected refs keeps every branch out.
	if workflowRestrictsToProtected(parser.Unwrap(doc)) {
		return nil
	}

	var findings []finding.Finding
	in := NewInheritance(doc)
	mapping := parser.Unwrap(doc)
	mrPipelines := !workflowRestrictsSource(mapping) || workflowAdmitsMR(mapping)

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
			if open, openWhy = unrestrictedRuleEntry(in.Key(job, "rules"), mrPipelines); open == nil {
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

// unrestrictedRuleEntry returns the first rules: entry that can run the job
// on any ref, and why (#1486). GitLab runs the job by the first entry that
// matches, so one such entry is enough, whatever the others restrict. An
// entry counts when it has no if: (changes:, exists: or when: alone), when
// its if: only tests that a branch is set, or when it admits merge request
// pipelines, which build the MR's unmerged source commit. An earlier when:
// never entry that keeps unprotected refs out restricts every entry after
// it. Other if: conditions (a pipeline source such as schedule or web, a
// project's own variable) depend on settings the file doesn't show and are
// left alone, as are rules glsec can't read (!reference).
func unrestrictedRuleEntry(rules *yaml.Node, mrPipelines bool) (*yaml.Node, string) {
	if rules == nil || rules.Kind != yaml.SequenceNode || parser.IsReference(rules) {
		return nil, ""
	}
	for _, item := range rules.Content {
		if parser.IsReference(item) || item.Kind != yaml.MappingNode {
			return nil, ""
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode != nil && ifNode.Kind != yaml.ScalarNode {
			return nil, ""
		}
		if ruleExcludes(item) {
			if ifNode == nil || excludesUnprotected(ifNode.Value) {
				return nil, ""
			}
			continue
		}
		if ifNode == nil {
			return item, ruleEntryWithoutIf(item)
		}
		expr := trimOuterParens(strings.TrimSpace(ifNode.Value))
		switch {
		case branchPresenceRe.MatchString(expr):
			return item, fmt.Sprintf("if: %s only checks that a branch is set", ifNode.Value)
		case mrPipelines && ifAdmitsMR(expr) && !ifRestrictsToProtected(expr):
			return item, fmt.Sprintf("if: %s admits merge request pipelines, which deploy the MR's source commit before anyone merged it", ifNode.Value)
		}
	}
	return nil, ""
}

func ruleEntryWithoutIf(item *yaml.Node) string {
	for _, key := range []string{"changes", "exists"} {
		if parser.FindKey(item, key) != nil {
			return "with " + key + ": and no if: matches on every branch"
		}
	}
	if w := parser.FindKey(item, "when"); w != nil && w.Kind == yaml.ScalarNode {
		return fmt.Sprintf("when: %s has no if: and matches on every branch", w.Value)
	}
	return "has no if: and matches on every branch"
}

var (
	// branchPresenceRe matches an if: that only tests that the pipeline has a
	// branch or ref name, which every branch does.
	branchPresenceRe = mustCompilePrefiltered(`^\$\{?CI_COMMIT_(?:BRANCH|REF_NAME)\}?(?:\s*!=\s*(?:null|""|''))?$`)
	// unprotectedExclusionRe matches a when: never condition that is true on
	// every unprotected ref: not protected, not the default or a named branch,
	// no tag, or a branch or tag that doesn't match a pattern (an unset
	// variable matches no pattern, so merge request pipelines are out too).
	unprotectedExclusionRe = mustCompilePrefiltered(`^(?:\$\{?CI_COMMIT_REF_PROTECTED\}?\s*(?:!=\s*["']true["']|==\s*["']false["'])|\$\{?CI_COMMIT_(?:BRANCH|REF_NAME)\}?\s*!=\s*(?:\$\{?CI_DEFAULT_BRANCH\}?|["'][^"']+["'])|\$\{?CI_DEFAULT_BRANCH\}?\s*!=\s*\$\{?CI_COMMIT_(?:BRANCH|REF_NAME)\}?|\$\{?CI_COMMIT_TAG\}?\s*==\s*(?:null|""|'')|\$\{?CI_COMMIT_(?:BRANCH|REF_NAME|TAG)\}?\s*!~\s*/.*/[a-z]*)$`)
)

// excludesUnprotected reports whether a when: never condition keeps every
// unprotected ref out: one of its || alternatives does.
func excludesUnprotected(expr string) bool {
	alts := splitTopLevel(trimOuterParens(strings.TrimSpace(expr)), "||")
	for _, alt := range alts {
		if unprotectedExclusionRe.MatchString(trimOuterParens(alt)) {
			return true
		}
	}
	return false
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

var (
	// mrSourceRe matches an operand that requires a merge request pipeline
	// by its source, in either operand order.
	mrSourceRe = mustCompilePrefiltered(`^(?:\$\{?CI_PIPELINE_SOURCE\}?\s*(?:==\s*["']merge_request_event["']|=~\s*/[^/]*merge_request[^/]*/[a-z]*)|["']merge_request_event["']\s*==\s*\$\{?CI_PIPELINE_SOURCE\}?)$`)
	// mrVarRe matches an operand that tests a merge request variable for
	// presence or a value; these are only set in merge request pipelines.
	mrVarRe = mustCompilePrefiltered(`^(?:\$\{?CI_MERGE_REQUEST_\w+\}?(?:\s*(?:==|=~)\s*(.+))?|(["'][^"']*["'])\s*==\s*\$\{?CI_MERGE_REQUEST_\w+\}?)$`)
	// branchOrTagRe matches an operand that tests the branch or tag of a
	// branch or tag pipeline; both are unset in a merge request pipeline.
	branchOrTagRe = mustCompilePrefiltered(`\$\{?CI_COMMIT_(?:BRANCH|TAG)\b`)
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
