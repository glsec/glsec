// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

// Whether a job can run on an unprotected ref or in a merge request pipeline,
// read from its rules: and the file's workflow:rules (#1493). GitLab evaluates
// rules: in order and uses the first entry that matches; a final when: entry
// matches on every ref.

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// refScope is what a file's workflow:rules let through.
type refScope struct {
	// protectedOnly: the workflow admits protected refs only, so no job in
	// the file runs on an unprotected branch or in a merge request pipeline.
	protectedOnly bool
	// mrPipelines: merge request pipelines can run.
	mrPipelines bool
}

func newRefScope(mapping *yaml.Node) refScope {
	return refScope{
		protectedOnly: workflowRestrictsToProtected(mapping),
		mrPipelines:   !workflowRestrictsSource(mapping) || workflowAdmitsMR(mapping),
	}
}

// openEntry returns the first rules: entry that lets the job run on any ref,
// and why; nil when every entry is restricted, the rules can't be read, or
// the workflow already keeps unprotected refs out.
func (s refScope) openEntry(rules *yaml.Node) (*yaml.Node, string) {
	if s.protectedOnly {
		return nil, ""
	}
	return unrestrictedRuleEntry(rules, s.mrPipelines, false)
}

// fallbackEntry is openEntry narrowed to entries without if: (#1498): a
// when: fallback such as - when: manual, or changes:/exists: alone, which is
// also true for new branches. An if: that only tests that a branch is set, or
// one that admits merge request pipelines, is not counted.
func (s refScope) fallbackEntry(rules *yaml.Node) (*yaml.Node, string) {
	if s.protectedOnly {
		return nil, ""
	}
	return unrestrictedRuleEntry(rules, s.mrPipelines, true)
}

type guardState int

const (
	guardAbsent      guardState = iota // no rules:/only:/except: at all
	guardIneffective                   // rules: present but no if:/changes:/exists: condition
	guardEffective                     // has a real restriction
)

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
func unrestrictedRuleEntry(rules *yaml.Node, mrPipelines, withoutIfOnly bool) (*yaml.Node, string) {
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
			// The narrow form only reports an entry without if: when nothing
			// before it can keep a ref out: an exclusion glsec can't read,
			// such as one on the pipeline source, may be what limits the
			// fallback after it (#1498).
			if ifNode == nil || excludesUnprotected(ifNode.Value) || withoutIfOnly {
				return nil, ""
			}
			continue
		}
		if ifNode == nil {
			return item, ruleEntryWithoutIf(item)
		}
		if withoutIfOnly {
			continue
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

// jobAdmitsMR reports whether a job's guard lets a merge-request pipeline run
// it: a rules:if that matches merge_request_event (and is not a when: never
// exclusion), or a legacy only: merge_requests clause.
func jobAdmitsMR(job *yaml.Node) bool {
	if onlyAdmitsMR(parser.FindKey(job, "only")) {
		return true
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rules.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if ruleExcludes(item) {
			continue
		}
		if ifNode := parser.FindKey(item, "if"); ifNode != nil && ifNode.Kind == yaml.ScalarNode && ifAdmitsMR(ifNode.Value) {
			return true
		}
	}
	return false
}

// onlyAdmitsMR reports whether a legacy only: clause admits merge_requests, in
// any of its scalar / sequence / refs: mapping shapes.
func onlyAdmitsMR(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value == "merge_requests"
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if onlyAdmitsMR(c) {
				return true
			}
		}
	case yaml.MappingNode:
		if refs := parser.FindKey(n, "refs"); refs != nil {
			return onlyAdmitsMR(refs)
		}
	}
	return false
}

// ruleExcludes reports whether a rules item is a when: never exclusion, which
// blocks rather than admits the sources it matches.
func ruleExcludes(item *yaml.Node) bool {
	w := parser.FindKey(item, "when")
	return w != nil && w.Kind == yaml.ScalarNode && w.Value == "never"
}

// ifAdmitsMR reports whether a rules:if expression admits merge-request
// pipelines. `$CI_PIPELINE_SOURCE != "merge_request_event"` matches everything
// *except* MRs, so a != comparison is not an admission.
func ifAdmitsMR(expr string) bool {
	return strings.Contains(expr, "merge_request_event") && !strings.Contains(expr, "!=")
}

var (
	// $CI_COMMIT_BRANCH / $CI_COMMIT_REF_NAME equal to the default branch or a
	// named branch, in either operand order.
	protDefaultBranchPat = mustCompilePrefiltered(`^\$CI_COMMIT_(BRANCH|REF_NAME)\s*==\s*\$CI_DEFAULT_BRANCH$|^\$CI_DEFAULT_BRANCH\s*==\s*\$CI_COMMIT_(BRANCH|REF_NAME)$`)
	protNamedBranchPat   = mustCompilePrefiltered(`^\$CI_COMMIT_(BRANCH|REF_NAME)\s*==\s*['"][^'"]+['"]$`)
	// A tag pipeline: the variable alone, a regex match on it, or != null.
	protTagPat       = mustCompilePrefiltered(`^\$CI_COMMIT_TAG(\s*=~\s*/.*/[a-z]*|\s*!=\s*null)?$`)
	protProtectedPat = mustCompilePrefiltered(`^\$CI_COMMIT_REF_PROTECTED\s*==\s*['"]true['"]$`)
)

// ifRestrictsToProtected reports whether a rules:if expression confines the job
// to a protected ref, tag, or a named branch: the default branch, a tag, an
// explicit CI_COMMIT_REF_PROTECTED == "true", or an explicit branch equality.
//
// && binds tighter than ||, as in GitLab. Every || alternative must restrict,
// because any one of them admits the pipeline; of && operands, one restricting
// operand is enough. An expression whose parentheses don't balance restricts
// nothing, so the error is a finding rather than a silenced one.
func ifRestrictsToProtected(expr string) bool {
	expr = trimOuterParens(strings.TrimSpace(expr))
	if alts := splitTopLevel(expr, "||"); len(alts) > 1 {
		for _, alt := range alts {
			if !ifRestrictsToProtected(alt) {
				return false
			}
		}
		return true
	}
	if ops := splitTopLevel(expr, "&&"); len(ops) > 1 {
		for _, op := range ops {
			if ifRestrictsToProtected(op) {
				return true
			}
		}
		return false
	}
	return operandRestrictsToProtected(expr)
}

// splitTopLevel splits expr at sep where sep is outside parentheses, quotes
// and /regex/ literals. It returns nil if the parentheses don't balance.
func splitTopLevel(expr, sep string) []string {
	code := exprCode(expr)
	if code == nil {
		return nil
	}
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(expr); i++ {
		if !code[i] {
			continue
		}
		switch {
		case expr[i] == '(':
			depth++
		case expr[i] == ')':
			depth--
			if depth < 0 {
				return nil
			}
		case depth == 0 && strings.HasPrefix(expr[i:], sep):
			parts = append(parts, strings.TrimSpace(expr[start:i]))
			i += len(sep) - 1
			start = i + 1
		}
	}
	if depth != 0 {
		return nil
	}
	return append(parts, strings.TrimSpace(expr[start:]))
}

// trimOuterParens removes parentheses that enclose the whole expression, but
// not the two in "(a) && (b)".
func trimOuterParens(expr string) string {
	for strings.HasPrefix(expr, "(") && closingParen(expr) == len(expr)-1 {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	return expr
}

// closingParen returns the index of the parenthesis that closes the one at
// expr[0], or -1.
func closingParen(expr string) int {
	code := exprCode(expr)
	depth := 0
	for i := range code {
		if !code[i] {
			continue
		}
		switch expr[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// exprCode marks the bytes of a rules:if expression that are outside quoted
// strings and /regex/ literals, so parentheses and operators inside them are
// not read as syntax. A regex literal only follows =~ or !~. It returns nil
// for an unterminated string or regex.
func exprCode(expr string) []bool {
	code := make([]bool, len(expr))
	var quote byte
	inRegex := false
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case inRegex:
			switch c {
			case '\\':
				i++
			case '/':
				inRegex = false
			}
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '/' && regexFollows(expr[:i]):
			inRegex = true
		default:
			code[i] = true
		}
	}
	if quote != 0 || inRegex {
		return nil
	}
	return code
}

func regexFollows(before string) bool {
	before = strings.TrimSpace(before)
	return strings.HasSuffix(before, "=~") || strings.HasSuffix(before, "!~")
}

func operandRestrictsToProtected(op string) bool {
	return protDefaultBranchPat.MatchString(op) ||
		protNamedBranchPat.MatchString(op) ||
		protTagPat.MatchString(op) ||
		protProtectedPat.MatchString(op)
}

// workflowRestrictsToProtected reports whether the top-level workflow:rules
// confine the pipeline to protected refs: every admitting rule carries an if:
// that restricts to a protected ref, and none admits merge_request_event. An
// unconditional or MR-admitting rule means the workflow does not protect the
// token, so it returns false.
func workflowRestrictsToProtected(mapping *yaml.Node) bool {
	wf := parser.FindKey(mapping, "workflow")
	if wf == nil {
		return false
	}
	rules := parser.FindKey(wf, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	sawProtected := false
	for _, item := range rules.Content {
		// An entry glsec can't read, such as a !reference into an included
		// file, may admit anything (#1492).
		if item.Kind != yaml.MappingNode || parser.IsReference(item) {
			return false
		}
		if ruleExcludes(item) {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
			return false // an unconditional allow admits every source
		}
		if ifAdmitsMR(ifNode.Value) || !ifRestrictsToProtected(ifNode.Value) {
			return false
		}
		sawProtected = true
	}
	return sawProtected
}

// workflowAdmitsMR reports whether workflow:rules, which
// workflowRestrictsSource found, can let a merge request pipeline run: a rule
// without if:, or one that tests a merge request or neither the branch, the
// tag nor the pipeline source.
func workflowAdmitsMR(mapping *yaml.Node) bool {
	rules := parser.FindKey(parser.FindKey(mapping, "workflow"), "rules")
	for _, item := range rules.Content {
		if item.Kind != yaml.MappingNode {
			return true
		}
		if ruleExcludes(item) {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
			return true
		}
		e := ifNode.Value
		if strings.Contains(e, "merge_request") || strings.Contains(e, "CI_MERGE_REQUEST_") ||
			!branchOrTagRe.MatchString(e) && !strings.Contains(e, "CI_PIPELINE_SOURCE") {
			return true
		}
	}
	return false
}

// jobGuardState classifies a job's execution guard. only:/except: (legacy) and
// any rules item carrying an if:/changes:/exists: condition count as effective.
func jobGuardState(job *yaml.Node) guardState {
	if only := parser.FindKey(job, "only"); only != nil && !isNullNode(only) {
		return guardEffective
	}
	if except := parser.FindKey(job, "except"); except != nil && !isNullNode(except) {
		return guardEffective
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil || isNullNode(rules) {
		return guardAbsent
	}
	// A !reference that points into an included file can't be read here: the
	// rules it stands for are unknown, so they count as a guard (#979).
	if rules.Kind != yaml.SequenceNode || parser.IsReference(rules) {
		return guardEffective
	}
	for _, item := range rules.Content {
		if parser.IsReference(item) {
			return guardEffective
		}
		if item.Kind != yaml.MappingNode {
			continue
		}
		if parser.FindKey(item, "if") != nil ||
			parser.FindKey(item, "changes") != nil ||
			parser.FindKey(item, "exists") != nil {
			return guardEffective
		}
	}
	return guardIneffective
}

// workflowRestrictsSource reports whether top-level workflow:rules carries any
// if: condition — treated as restricting which pipeline sources run at all.
func workflowRestrictsSource(mapping *yaml.Node) bool {
	wf := parser.FindKey(mapping, "workflow")
	if wf == nil {
		return false
	}
	rules := parser.FindKey(wf, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rules.Content {
		if item.Kind == yaml.MappingNode && parser.FindKey(item, "if") != nil {
			return true
		}
	}
	return false
}
