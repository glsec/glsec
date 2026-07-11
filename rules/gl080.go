package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl080 struct{}

var GL080 = &gl080{}

func (r *gl080) ID() string { return "GL080" }

func (r *gl080) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)

	// A restricting top-level workflow:rules gates every job's pipeline source,
	// so no job needs its own guard. Suppress conservatively: any workflow:rules
	// carrying an if: condition is treated as restricting the source.
	if workflowRestrictsSource(mapping) {
		return nil
	}

	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !IsDeployLikeJob(name.Value, job) {
			return
		}
		// The production-environment-without-rules case is already covered by
		// GL013; skip it here to avoid a duplicate finding.
		if gl013Owns(job) {
			return
		}
		state := jobGuardState(job)
		if state == guardEffective {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL080",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  gl080Message(name.Value, state),
			File:     file,
			Line:     name.Line,
			Col:      name.Column,
		})
	})
	return findings
}

type guardState int

const (
	guardAbsent      guardState = iota // no rules:/only:/except: at all
	guardIneffective                   // rules: present but no if:/changes:/exists: condition
	guardEffective                     // has a real restriction
)

func gl080Message(job string, state guardState) string {
	if state == guardIneffective {
		return fmt.Sprintf(
			"sensitive job %q has a rules: block with no if:/changes:/exists: condition — the gate imposes no restriction, so the job runs on every pipeline source including fork merge requests; add a rules:if that checks $CI_PIPELINE_SOURCE",
			job,
		)
	}
	return fmt.Sprintf(
		"sensitive job %q has no rules:/only:/except: guard — it runs on every pipeline source including fork merge requests; add a rules:if that checks $CI_PIPELINE_SOURCE",
		job,
	)
}

// jobGuardState classifies a job's execution guard. only:/except: (legacy) and
// any rules item carrying an if:/changes:/exists: condition count as effective.
func jobGuardState(job *yaml.Node) guardState {
	if parser.FindKey(job, "only") != nil || parser.FindKey(job, "except") != nil {
		return guardEffective
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil {
		return guardAbsent
	}
	if rules.Kind != yaml.SequenceNode {
		return guardEffective
	}
	for _, item := range rules.Content {
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

// gl013Owns reports whether GL013 already flags this job (a production-like
// environment with no rules:/only: restriction), so GL080 can defer to it.
func gl013Owns(job *yaml.Node) bool {
	env := parser.FindKey(job, "environment")
	if env == nil {
		return false
	}
	envName := extractEnvName(env)
	tier := extractDeploymentTier(env)
	prod := (envName != "" && isProdEnv(envName)) || isProdTier(tier)
	return prod && !hasExecutionRestriction(job)
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
