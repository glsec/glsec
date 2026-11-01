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

	in := NewInheritance(doc)
	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// Hidden jobs (names starting with ".") are templates GitLab never runs.
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		// A base in another file may hold the guard: skip the job rather than
		// report a guard that is present but invisible here. A chain within
		// this file is merged in.
		if !in.ExtendsResolved(job) || in.IncludedOverride(job) {
			return
		}
		job = in.Effective(job)
		if !gl080Sensitive(name.Value, job) {
			return
		}
		// The production-environment-without-rules case is already covered by
		// GL013; skip it here to avoid a duplicate finding.
		if gl013Owns(name.Value, job) {
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
			Message:  gl080Message(name.Value, state, jobManualOnly(job)),
			File:     file,
			Line:     name.Line,
			Col:      name.Column,
		})
	})
	return findings
}

// gl080DeployKeywords are the narrow set of job/stage name fragments that
// reliably indicate a deployment or external publish. Broader terms used
// elsewhere (push, upload, dist, ship, migrate) matched too many build/cache
// jobs in real pipelines, so they are intentionally excluded here.
var gl080DeployKeywords = []string{"deploy", "rollout", "release", "publish", "provision"}

// gl080NotDeployKeywords mark jobs that only build, test, or package artifacts —
// e.g. a "release build" or "docdist" is not a deployment. They veto a keyword
// match so "windows-release-build" or "coverage-review" is not flagged.
var gl080NotDeployKeywords = []string{
	"build", "compile", "test", "lint", "cache", "coverage",
	"check", "package", "bundle", "prepare", "validate", "audit",
	"scan", "review", "dist",
}

// gl080Sensitive reports whether a job deploys or publishes to an external
// target. An environment: (other than a teardown/stop job) is the strongest
// signal; otherwise a narrow deploy keyword in the job or stage name, unless a
// build/test/package keyword vetoes it.
func gl080Sensitive(name string, job *yaml.Node) bool {
	if env := parser.FindKey(job, "environment"); env != nil && !envActionStop(env) && extractEnvName(env) != "" {
		return true
	}
	hay := strings.ToLower(name) + " " + jobStageName(job)
	for _, neg := range gl080NotDeployKeywords {
		if strings.Contains(hay, neg) {
			return false
		}
	}
	for _, kw := range gl080DeployKeywords {
		if strings.Contains(hay, kw) {
			return true
		}
	}
	return false
}

func jobStageName(job *yaml.Node) string {
	if s := parser.FindKey(job, "stage"); s != nil && s.Kind == yaml.ScalarNode {
		return strings.ToLower(s.Value)
	}
	return ""
}

// envActionStop reports whether an environment: block is a teardown job
// (environment:action: stop), which tears an environment down rather than
// deploying to it and carries little source-guard risk.
func envActionStop(env *yaml.Node) bool {
	if env.Kind != yaml.MappingNode {
		return false
	}
	if a := parser.FindKey(env, "action"); a != nil && a.Kind == yaml.ScalarNode {
		return a.Value == "stop"
	}
	return false
}

type guardState int

const (
	guardAbsent      guardState = iota // no rules:/only:/except: at all
	guardIneffective                   // rules: present but no if:/changes:/exists: condition
	guardEffective                     // has a real restriction
)

func gl080Message(job string, state guardState, manual bool) string {
	// when: manual is the job's only gate. It is not a pipeline-source
	// restriction: the job is still created on every source, and a maintainer
	// can start it on a fork merge request, where it runs the fork's code with
	// this job's credentials. So GL080 still flags it, but the message says so
	// accurately rather than claiming an external contributor can trigger it
	// (#1124).
	if manual {
		return fmt.Sprintf(
			"sensitive job %q is gated only by when: manual, which is not a pipeline-source restriction — a maintainer can still start it on a fork merge request, where it runs untrusted code with this job's credentials; add a rules:if that checks $CI_PIPELINE_SOURCE",
			job,
		)
	}
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

// jobManualOnly reports whether the job's trigger gate is when: manual — a
// top-level when: manual, or a rules: item that sets when: manual. A manual
// gate is not a pipeline-source restriction, so GL080 keeps flagging the job
// but words the finding for the manual case (#1124).
func jobManualOnly(job *yaml.Node) bool {
	if w := parser.FindKey(job, "when"); w != nil && w.Kind == yaml.ScalarNode {
		return w.Value == "manual"
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rules.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if w := parser.FindKey(item, "when"); w != nil && w.Kind == yaml.ScalarNode && w.Value == "manual" {
			return true
		}
	}
	return false
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

// gl013Owns reports whether GL013 already flags this job (a production-like
// environment or the main Pages site, with no rules:/only: restriction), so
// GL080 can defer to it.
func gl013Owns(name string, job *yaml.Node) bool {
	if !hasExecutionRestriction(job) && publishesMainPages(name, parser.FindKey(job, "pages")) {
		return true
	}
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
