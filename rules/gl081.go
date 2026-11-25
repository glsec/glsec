// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl081 struct {
	restricted map[string]bool
}

var GL081 = &gl081{}

func (r *gl081) ID() string { return "GL081" }

// SetRestrictedAudiences configures the id_tokens audiences the project
// restricts on the cloud side (restricted_oidc_audiences). A job whose tokens
// only use such audiences is reported as info: minting them on any branch or
// merge request is by design, but what they can read still is (#1484).
func (r *gl081) SetRestrictedAudiences(auds []string) {
	r.restricted = nil
	for _, a := range auds {
		if a != "" {
			if r.restricted == nil {
				r.restricted = map[string]bool{}
			}
			r.restricted[a] = true
		}
	}
}

// CheckDocument reads the file in its pipeline context (#1502): a child
// pipeline or included file that only protected refs reach has no job that
// runs on an unprotected branch, and in a child pipeline started on any ref,
// if: $CI_PIPELINE_SOURCE == "parent_pipeline" restricts nothing.
func (r *gl081) CheckDocument(doc *parser.Document, file string) []finding.Finding {
	ctx := contextOf(doc)
	if ctx.protected {
		return nil
	}
	return r.check(doc.Root, file, ctx)
}

func (r *gl081) Check(doc *yaml.Node, file string) []finding.Finding {
	return r.check(doc, file, docContext{})
}

func (r *gl081) check(doc *yaml.Node, file string, ctx docContext) []finding.Finding {
	mapping := parser.Unwrap(doc)

	// A top-level workflow:rules that confines the pipeline to protected refs
	// means no job in the file can run on a merge request or an unprotected
	// branch, so no id_tokens: job can mint a token there — suppress the whole
	// file. Note this is stricter than GL080's workflowRestrictsSource: a
	// workflow that merely carries an if: but still admits merge_request_event
	// does not protect the token and must not suppress here.
	scope := ctx.scope(mapping)
	if scope.protectedOnly {
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
			findings = append(findings, r.finding(name, job, file, cred, gl081ReasonAdmits, ""))
			return
		}

		// Otherwise fall back to the same guard classification as GL080: an
		// absent or condition-less guard leaves the source unrestricted. An
		// effective guard (restricted to a protected ref, tag, or branch) is
		// accepted.
		if jobGuardState(job) != guardEffective {
			findings = append(findings, r.finding(name, job, file, cred, gl081ReasonUnguarded, ""))
			return
		}
		// A guard is no restriction when one of its rules: entries matches
		// on any branch: GitLab runs the job by the first entry that matches
		// (#1491).
		if entry, why := scope.openEntry(parser.FindKey(job, "rules")); entry != nil {
			findings = append(findings, r.finding(name, job, file, cred, gl081ReasonOpenEntry, why))
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
	// gl081ReasonOpenEntry: a rules: entry that runs the job matches on any
	// branch; the finding carries which entry and why.
	gl081ReasonOpenEntry
)

func (r *gl081) finding(name, job *yaml.Node, file string, cred gl081Credential, reason gl081Reason, entry string) finding.Finding {
	f := finding.Finding{
		RuleID:   "GL081",
		Severity: finding.Warn,
		Job:      name.Value,
		File:     file,
		Line:     name.Line,
		Col:      name.Column,
	}
	if cred == credIdentity {
		f.Message = gl081IdentityMessage(name.Value, reason, entry)
		return f
	}
	open, restricted := r.tokens(job)
	if len(open) == 0 && len(restricted) > 0 {
		f.Severity = finding.Info
		f.Message = gl081RestrictedMessage(name.Value, restricted, reason, entry)
		return f
	}
	if len(open) == 0 {
		open = restricted
	}
	f.Message = gl081TokenMessage(name.Value, open, reason, entry)
	return f
}

// tokens splits the job's id_tokens into those with an audience the project
// hasn't declared restricted and those whose every aud: is declared. An aud:
// built from a variable, or a token without one, can't be matched and counts
// as not declared.
func (r *gl081) tokens(job *yaml.Node) (open, restricted []string) {
	t := parser.FindKey(job, "id_tokens")
	if t == nil || t.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(t.Content); i += 2 {
		name := t.Content[i].Value
		if r.declared(t.Content[i+1]) {
			restricted = append(restricted, name)
		} else {
			open = append(open, name)
		}
	}
	return open, restricted
}

func (r *gl081) declared(tokenDef *yaml.Node) bool {
	if len(r.restricted) == 0 || tokenDef.Kind != yaml.MappingNode {
		return false
	}
	aud := parser.FindKey(tokenDef, "aud")
	if aud == nil {
		return false
	}
	values := []*yaml.Node{aud}
	if aud.Kind == yaml.SequenceNode {
		values = aud.Content
	}
	if len(values) == 0 {
		return false
	}
	for _, v := range values {
		if v.Kind != yaml.ScalarNode || strings.Contains(v.Value, "$") || !r.restricted[v.Value] {
			return false
		}
	}
	return true
}

// tokenList names the tokens a finding is about: "token X" or "tokens X, Y".
func tokenList(names []string) string {
	if len(names) == 1 {
		return "token " + names[0]
	}
	return "tokens " + strings.Join(names, ", ")
}

func gl081IdentityMessage(job string, reason gl081Reason, entry string) string {
	if reason == gl081ReasonOpenEntry {
		return fmt.Sprintf(
			"job %q gets Google Cloud credentials through identity:, but its rules: entry %s — any branch can use them; restrict every rules: entry that runs the job to protected refs and add the attribute condition assertion.ref_protected == \"true\" to the workload identity provider",
			job, entry,
		)
	}
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

func gl081TokenMessage(job string, tokens []string, reason gl081Reason, entry string) string {
	if reason == gl081ReasonOpenEntry {
		return fmt.Sprintf(
			"job %q issues OIDC %s (id_tokens:), but its rules: entry %s — any branch can mint a cloud-federating token; restrict every rules: entry that runs the job to protected refs and condition the cloud trust policy on the ref_protected claim",
			job, tokenList(tokens), entry,
		)
	}
	if reason == gl081ReasonAdmits {
		return fmt.Sprintf(
			"job %q issues OIDC %s (id_tokens:) and its guard admits merge_request_event — any merge request can mint a cloud-federating token; restrict the job to protected refs and condition the cloud trust policy on the ref_protected claim",
			job, tokenList(tokens),
		)
	}
	return fmt.Sprintf(
		"job %q issues OIDC %s (id_tokens:) with no guard restricting $CI_PIPELINE_SOURCE or the ref — any branch or merge request can mint a cloud-federating token; add a rules:if that restricts to protected refs and condition the cloud trust policy on the ref_protected claim",
		job, tokenList(tokens),
	)
}

func gl081RestrictedMessage(job string, tokens []string, reason gl081Reason, entry string) string {
	where := "with no guard restricting $CI_PIPELINE_SOURCE or the ref"
	switch reason {
	case gl081ReasonAdmits:
		where = "and its guard admits merge_request_event"
	case gl081ReasonOpenEntry:
		where = "and its rules: entry " + entry
	}
	it := "it"
	if len(tokens) > 1 {
		it = "them"
	}
	return fmt.Sprintf(
		"job %q issues OIDC %s (id_tokens:) %s, but every audience is listed in restricted_oidc_audiences — any branch or merge request can mint %s by design; make sure the cloud side grants %s no more than read access, and that what %s reads (such as Terraform state) holds no secrets",
		job, tokenList(tokens), where, it, it, it,
	)
}
