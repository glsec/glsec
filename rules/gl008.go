package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl008 struct{}

var GL008 = &gl008{}

func (r *gl008) ID() string { return "GL008" }

// securityScanJobs are the GitLab-defined job names created when security
// scan templates are included. Failing these jobs with allow_failure: true
// causes GitLab to silently skip security result ingestion.
var securityScanJobs = map[string]bool{
	"sast":                  true,
	"sast-iac":              true,
	"secret_detection":      true,
	"dast":                  true,
	"dast_api":              true,
	"container_scanning":    true,
	"dependency_scanning":   true,
	"coverage_fuzzing":      true,
	"api_fuzzing":           true,
	"license_scanning":      true,
}

func (r *gl008) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !securityScanJobs[name.Value] {
			return
		}
		findings = append(findings, r.checkAllowFailure(name, job, file)...)
		findings = append(findings, r.checkNeverRuns(name, job, file)...)
	})

	return findings
}

func (r *gl008) checkAllowFailure(name, job *yaml.Node, file string) []finding.Finding {
	af := parser.FindKey(job, "allow_failure")
	if af == nil {
		return nil
	}
	// Only flag scalar `true`; allow_failure: {exit_codes: [...]} is intentional.
	if af.Kind != yaml.ScalarNode || af.Value != "true" {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "GL008",
		Severity: finding.Warn,
		Job:      name.Value,
		Message: fmt.Sprintf(
			"security scan job %q has allow_failure: true — scan failures are silently ignored and security results may not be ingested by GitLab",
			name.Value,
		),
		File: file,
		Line: af.Line,
		Col:  af.Column,
	}}
}

// checkNeverRuns covers the two ways a scan job is silenced without touching
// allow_failure: made manual, or given a rule that unconditionally prevents it
// from running. Both are deliberately narrow — see whenNeverRuns.
func (r *gl008) checkNeverRuns(name, job *yaml.Node, file string) []finding.Finding {
	rulesNode := parser.FindKey(job, "rules")

	if rulesNode == nil {
		w := parser.FindKey(job, "when")
		if w == nil || w.Kind != yaml.ScalarNode || w.Value != "manual" {
			return nil
		}
		return []finding.Finding{{
			RuleID:   "GL008",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"security scan job %q is when: manual — it never runs on its own, so a green pipeline says nothing about whether the code was scanned",
				name.Value,
			),
			File: file,
			Line: w.Line,
			Col:  w.Column,
		}}
	}

	entry := soleUnconditionalRule(rulesNode)
	if entry == nil {
		return nil
	}
	w := parser.FindKey(entry, "when")
	if w == nil || w.Kind != yaml.ScalarNode {
		return nil
	}

	var msg string
	switch w.Value {
	case "never":
		msg = fmt.Sprintf(
			"security scan job %q has rules: [when: never] as its only rule — the job is switched off in every context",
			name.Value,
		)
	case "manual":
		msg = fmt.Sprintf(
			"security scan job %q has rules: [when: manual] as its only rule — it never runs on its own, so a green pipeline says nothing about whether the code was scanned",
			name.Value,
		)
	default:
		return nil
	}

	return []finding.Finding{{
		RuleID:   "GL008",
		Severity: finding.Warn,
		Job:      name.Value,
		Message:  msg,
		File:     file,
		Line:     w.Line,
		Col:      w.Column,
	}}
}

// soleUnconditionalRule returns the single rules: entry of a job when that
// entry carries no condition, and nil otherwise.
//
// The narrowness is the point. A conditional `when: never` is how GitLab's own
// templates express their kill switch (`- if: $SAST_DISABLED / when: never`),
// and overriding a scan job's rules while keeping that entry is idiomatic — the
// dangerous half of it, actually setting the variable, is GL082's job. An
// unconditional `when: never` trailing a list of conditional rules is the
// equally idiomatic "otherwise don't run" catch-all. Only a lone, unconditional
// entry disables the job outright in every context.
func soleUnconditionalRule(rulesNode *yaml.Node) *yaml.Node {
	if rulesNode.Kind != yaml.SequenceNode || len(rulesNode.Content) != 1 {
		return nil
	}
	entry := rulesNode.Content[0]
	if entry.Kind != yaml.MappingNode {
		return nil
	}
	for _, cond := range []string{"if", "changes", "exists"} {
		if parser.FindKey(entry, cond) != nil {
			return nil
		}
	}
	return entry
}
