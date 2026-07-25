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

	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// Hidden jobs (names starting with ".") are templates GitLab never runs.
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		if !hasIDTokens(job) {
			return
		}
		// A job that pulls config in via extends: or a YAML merge (<<:) may
		// inherit its guard from a base glsec does not resolve — skip it.
		if inheritsConfig(job) {
			return
		}

		// A guard that explicitly admits merge_request_event (or the legacy
		// only: merge_requests) lets any MR mint the token, even one that is
		// otherwise an "effective" restriction on some other ref.
		if jobAdmitsMR(job) {
			findings = append(findings, gl081Finding(name, file, gl081ReasonAdmits))
			return
		}

		// Otherwise fall back to the same guard classification as GL080: an
		// absent or condition-less guard leaves the source unrestricted. An
		// effective guard (restricted to a protected ref, tag, or branch) is
		// accepted.
		if jobGuardState(job) != guardEffective {
			findings = append(findings, gl081Finding(name, file, gl081ReasonUnguarded))
		}
	})
	return findings
}

func hasIDTokens(job *yaml.Node) bool {
	t := parser.FindKey(job, "id_tokens")
	return t != nil && t.Kind == yaml.MappingNode
}

type gl081Reason int

const (
	gl081ReasonAdmits gl081Reason = iota
	gl081ReasonUnguarded
)

func gl081Finding(name *yaml.Node, file string, reason gl081Reason) finding.Finding {
	return finding.Finding{
		RuleID:   "GL081",
		Severity: finding.Warn,
		Job:      name.Value,
		Message:  gl081Message(name.Value, reason),
		File:     file,
		Line:     name.Line,
		Col:      name.Column,
	}
}

func gl081Message(job string, reason gl081Reason) string {
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

var branchEqPat = regexp.MustCompile(`\$CI_COMMIT_(BRANCH|REF_NAME)\s*==\s*['"]`)

// ifRestrictsToProtected reports whether a rules:if expression confines the job
// to a protected ref, tag, or a named branch: the default branch, a tag, an
// explicit CI_COMMIT_REF_PROTECTED == "true", or an explicit branch equality.
func ifRestrictsToProtected(expr string) bool {
	switch {
	case strings.Contains(expr, "$CI_DEFAULT_BRANCH"):
		return true
	case strings.Contains(expr, "$CI_COMMIT_TAG") && !strings.Contains(expr, "!=") && !strings.Contains(expr, "== null"):
		return true
	case strings.Contains(expr, "$CI_COMMIT_REF_PROTECTED") && strings.Contains(expr, "true"):
		return true
	case branchEqPat.MatchString(expr):
		return true
	}
	return false
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
