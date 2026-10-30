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

type gl008 struct{}

var GL008 = &gl008{}

func (r *gl008) ID() string { return "GL008" }

// securityScanJobs are the GitLab-defined job names created when security
// scan templates are included. Failing these jobs with allow_failure: true
// causes GitLab to silently skip security result ingestion. The SAST and
// Dependency Scanning analyzer jobs are listed because they do the actual
// scanning (names from the current templates; analyzers deprecated in GitLab
// 16.8 are left out).
var securityScanJobs = map[string]bool{
	"sast":                                 true,
	"secret_detection":                     true,
	"dast":                                 true,
	"dast_api":                             true,
	"container_scanning":                   true,
	"dependency_scanning":                  true,
	"coverage_fuzzing":                     true,
	"api_fuzzing":                          true,
	"license_scanning":                     true,
	"iac-sast":                             true,
	"kics-iac-sast":                        true,
	"gitlab-advanced-sast":                 true,
	"gitlab-advanced-sast-cpp":             true,
	"gitlab-advanced-sast-ext":             true,
	"gosec-sast":                           true,
	"spotbugs-sast":                        true,
	"bandit-sast":                          true,
	"eslint-sast":                          true,
	"kubesec-sast":                         true,
	"pmd-apex-sast":                        true,
	"security-code-scan-sast":              true,
	"semgrep-sast":                         true,
	"sobelow-sast":                         true,
	"gemnasium-dependency_scanning":        true,
	"gemnasium-maven-dependency_scanning":  true,
	"gemnasium-python-dependency_scanning": true,
}

// templateAllowFailureJobs already get allow_failure: true from their
// template (.sast-analyzer, .ds-analyzer, .secret-analyzer, container_scanning,
// iac-sast), so setting it again changes nothing and is not reported.
var templateAllowFailureJobs = map[string]bool{
	"secret_detection":                     true,
	"container_scanning":                   true,
	"iac-sast":                             true,
	"kics-iac-sast":                        true,
	"semgrep-sast":                         true,
	"gitlab-advanced-sast":                 true,
	"gitlab-advanced-sast-cpp":             true,
	"gitlab-advanced-sast-ext":             true,
	"gosec-sast":                           true,
	"spotbugs-sast":                        true,
	"bandit-sast":                          true,
	"eslint-sast":                          true,
	"kubesec-sast":                         true,
	"pmd-apex-sast":                        true,
	"security-code-scan-sast":              true,
	"sobelow-sast":                         true,
	"gemnasium-dependency_scanning":        true,
	"gemnasium-maven-dependency_scanning":  true,
	"gemnasium-python-dependency_scanning": true,
}

// configurationOnlyJobs never run: the templates give them rules: [when: never]
// and every analyzer has its own rules:, so neither allow_failure nor disabling
// them has any effect. Disabled scans are caught on the analyzer jobs and by
// GL082.
var configurationOnlyJobs = map[string]bool{
	"sast":                true,
	"dependency_scanning": true,
}

func (r *gl008) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !securityScanJobs[name.Value] || configurationOnlyJobs[name.Value] {
			return
		}
		job = in.Effective(job)
		if !templateAllowFailureJobs[name.Value] {
			findings = append(findings, r.checkAllowFailure(name, job, file)...)
		}
		// Switched off under its template name but run by a job that
		// extends it with rules of its own: the scan still runs (#1000).
		if !runByExtendingJob(doc, in, name.Value) {
			findings = append(findings, r.checkNeverRuns(name, job, file)...)
		}
	})

	return findings
}

// runByExtendingJob reports whether a visible job in the file extends the
// job named scan and runs: its effective rules aren't a lone when: never or
// when: manual.
func runByExtendingJob(doc *yaml.Node, in *Inheritance, scan string) bool {
	runs := false
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if runs || name.Value == scan || strings.HasPrefix(name.Value, ".") || !extendsJob(job, scan) {
			return
		}
		rules := parser.FindKey(in.Effective(job), "rules")
		if rules == nil {
			return // inherits the scan job's own rules
		}
		if entry := soleUnconditionalRule(rules); entry != nil {
			if w := parser.FindKey(entry, "when"); w != nil && (w.Value == "never" || w.Value == "manual") {
				return
			}
		}
		runs = true
	})
	return runs
}

// extendsJob reports whether job's extends: names target.
func extendsJob(job *yaml.Node, target string) bool {
	ext := parser.FindKey(job, "extends")
	if ext == nil {
		return false
	}
	if ext.Kind == yaml.ScalarNode {
		return ext.Value == target
	}
	for _, e := range ext.Content {
		if e.Kind == yaml.ScalarNode && e.Value == target {
			return true
		}
	}
	return false
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
