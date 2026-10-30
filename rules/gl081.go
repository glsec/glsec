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

type gl081 struct{}

var GL081 = &gl081{}

func (r *gl081) ID() string { return "GL081" }

func (r *gl081) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)

	// A top-level workflow:rules that confines the pipeline to protected refs
	// means no job in the file can run on a merge request or an unprotected
	// branch, so no id_tokens: job can mint a token there — suppress the whole
	// file. Note this is stricter than GL080's workflowRestrictsSource: a
	// workflow that merely carries an if: but still admits merge_request_event
	// does not protect the token and must not suppress here.
	if workflowRestrictsToProtected(mapping) {
		return nil
	}

	in := NewInheritance(doc)
	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// Hidden jobs (names starting with ".") are templates GitLab never runs.
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		// A base in another file may hold the guard or the credential: skip
		// the job. A chain within this file is merged in.
		if (!in.Has(job, "id_tokens") && !in.Has(job, "identity")) || !in.ExtendsResolved(job) || in.IncludedOverride(job) {
			return
		}
		job = in.Effective(job)
		cred := jobCredential(job)
		if cred == credNone {
			return
		}

		// A guard that explicitly admits merge_request_event (or the legacy
		// only: merge_requests) lets any MR mint the token, even one that is
		// otherwise an "effective" restriction on some other ref.
		if jobAdmitsMR(job) {
			findings = append(findings, gl081Finding(name, file, cred, gl081ReasonAdmits))
			return
		}

		// Otherwise fall back to the same guard classification as GL080: an
		// absent or condition-less guard leaves the source unrestricted. An
		// effective guard (restricted to a protected ref, tag, or branch) is
		// accepted.
		if jobGuardState(job) != guardEffective {
			findings = append(findings, gl081Finding(name, file, cred, gl081ReasonUnguarded))
		}
	})
	return findings
}

func hasIDTokens(job *yaml.Node) bool {
	t := parser.FindKey(job, "id_tokens")
	return t != nil && t.Kind == yaml.MappingNode
}

type gl081Credential int

const (
	credNone gl081Credential = iota
	credIDTokens
	// credIdentity is identity: google_cloud, Google Cloud credentials
	// through workload identity federation without an id_tokens: block.
	credIdentity
)

func jobCredential(job *yaml.Node) gl081Credential {
	if hasIDTokens(job) {
		return credIDTokens
	}
	if id := parser.FindKey(job, "identity"); id != nil && id.Kind == yaml.ScalarNode && id.Value != "" {
		return credIdentity
	}
	return credNone
}

type gl081Reason int

const (
	gl081ReasonAdmits gl081Reason = iota
	gl081ReasonUnguarded
)

func gl081Finding(name *yaml.Node, file string, cred gl081Credential, reason gl081Reason) finding.Finding {
	return finding.Finding{
		RuleID:   "GL081",
		Severity: finding.Warn,
		Job:      name.Value,
		Message:  gl081Message(name.Value, cred, reason),
		File:     file,
		Line:     name.Line,
		Col:      name.Column,
	}
}

func gl081Message(job string, cred gl081Credential, reason gl081Reason) string {
	if cred == credIdentity {
		if reason == gl081ReasonAdmits {
			return fmt.Sprintf(
				"job %q gets Google Cloud credentials through identity: and its guard admits merge_request_event — any merge request can use them; restrict the job to protected refs and add the attribute condition assertion.ref_protected == \"true\" to the workload identity provider",
				job,
			)
		}
		return fmt.Sprintf(
			"job %q gets Google Cloud credentials through identity: with no guard restricting $CI_PIPELINE_SOURCE or the ref — any branch or merge request can use them; add a rules:if that restricts to protected refs and the attribute condition assertion.ref_protected == \"true\" to the workload identity provider",
			job,
		)
	}
	if reason == gl081ReasonAdmits {
		return fmt.Sprintf(
			"job %q issues an OIDC id_tokens: credential and its guard admits merge_request_event — any merge request can mint a cloud-federating token; restrict the job to protected refs and condition the cloud trust policy on the ref_protected claim",
			job,
		)
	}
	return fmt.Sprintf(
		"job %q issues an OIDC id_tokens: credential with no guard restricting $CI_PIPELINE_SOURCE or the ref — any branch or merge request can mint a cloud-federating token; add a rules:if that restricts to protected refs and condition the cloud trust policy on the ref_protected claim",
		job,
	)
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
	protDefaultBranchPat = regexp.MustCompile(`^\$CI_COMMIT_(BRANCH|REF_NAME)\s*==\s*\$CI_DEFAULT_BRANCH$|^\$CI_DEFAULT_BRANCH\s*==\s*\$CI_COMMIT_(BRANCH|REF_NAME)$`)
	protNamedBranchPat   = regexp.MustCompile(`^\$CI_COMMIT_(BRANCH|REF_NAME)\s*==\s*['"][^'"]+['"]$`)
	// A tag pipeline: the variable alone, a regex match on it, or != null.
	protTagPat       = regexp.MustCompile(`^\$CI_COMMIT_TAG(\s*=~\s*/.*/[a-z]*|\s*!=\s*null)?$`)
	protProtectedPat = regexp.MustCompile(`^\$CI_COMMIT_REF_PROTECTED\s*==\s*['"]true['"]$`)
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
		if item.Kind != yaml.MappingNode {
			continue
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
