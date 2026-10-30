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

type gl071 struct{}

var GL071 = &gl071{}

func (r *gl071) ID() string { return "GL071" }

// defaultStages is GitLab's implicit stage order when no top-level stages: is
// declared. A job without an explicit stage: lands in "test".
var defaultStages = []string{".pre", "build", "test", "deploy", ".post"}

const defaultStage = "test"

func (r *gl071) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	stageIdx := buildStageIndex(mapping)
	in := NewInheritance(doc)

	// Production-like deploy jobs, with their stage.
	type deploy struct {
		idx int
		job *yaml.Node
	}
	var deploys []deploy
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if isHiddenJob(name.Value) || !in.Has(job, "environment") {
			return
		}
		job = in.Effective(job)
		if !isProdDeployJob(job) {
			return
		}
		if idx, ok := jobStageIndex(job, stageIdx); ok {
			deploys = append(deploys, deploy{idx, job})
		}
	})
	if len(deploys) == 0 {
		return nil
	}

	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if isHiddenJob(name.Value) || !in.Has(job, "when") {
			return
		}
		job = in.Effective(job)
		when := parser.FindKey(job, "when")
		if when == nil || when.Kind != yaml.ScalarNode || when.Value != "manual" {
			return
		}
		// rules: govern allow_failure (manual inside rules defaults to blocking),
		// so a top-level when: is moot — don't second-guess it.
		if parser.FindKey(job, "rules") != nil {
			return
		}
		// Explicitly blocking — this is the recommended fix, not a finding.
		if allowFailureFalse(job) {
			return
		}
		// A manual deploy job is a legitimate pattern; the gate problem is a
		// separate approval job, so skip jobs that deploy themselves.
		if parser.FindKey(job, "environment") != nil {
			return
		}
		idx, ok := jobStageIndex(job, stageIdx)
		if !ok {
			return
		}
		// The gate has to come before a deploy that can be in the same
		// pipeline: a gate with only: [develop] doesn't gate a deploy with
		// only: [main].
		gates := false
		for _, d := range deploys {
			if d.idx > idx && !disjointOnlyRefs(job, d.job) {
				gates = true
				break
			}
		}
		if !gates {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL071",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"manual job %q runs before a production deploy but does not set allow_failure: false — by default it is an optional gate, so later stages run and the pipeline can deploy without it being triggered; add allow_failure: false (or move when: manual into rules:)",
				name.Value,
			),
			File: file,
			Line: when.Line,
			Col:  when.Column,
		})
	})

	return findings
}

// disjointOnlyRefs reports whether two jobs are limited by only: to plain
// branch or tag names that have none in common, so they never run in the
// same pipeline. Keywords (branches, tags, merge_requests, …), regexes and
// rules: make the answer unknown, which counts as not disjoint.
func disjointOnlyRefs(a, b *yaml.Node) bool {
	ra, ok := plainOnlyRefs(a)
	if !ok {
		return false
	}
	rb, ok := plainOnlyRefs(b)
	if !ok {
		return false
	}
	for r := range ra {
		if rb[r] {
			return false
		}
	}
	return true
}

var onlyKeywords = map[string]bool{
	"branches": true, "tags": true, "merge_requests": true, "api": true, "external": true,
	"pipelines": true, "pushes": true, "schedules": true, "triggers": true, "web": true,
	"chat": true, "external_pull_requests": true,
}

func plainOnlyRefs(job *yaml.Node) (map[string]bool, bool) {
	if parser.FindKey(job, "rules") != nil {
		return nil, false
	}
	only := parser.FindKey(job, "only")
	if only != nil && only.Kind == yaml.MappingNode {
		only = parser.FindKey(only, "refs")
	}
	if only == nil || only.Kind != yaml.SequenceNode || len(only.Content) == 0 {
		return nil, false
	}
	refs := map[string]bool{}
	for _, r := range only.Content {
		if r.Kind != yaml.ScalarNode || onlyKeywords[r.Value] || strings.HasPrefix(r.Value, "/") {
			return nil, false
		}
		refs[r.Value] = true
	}
	return refs, true
}

func buildStageIndex(mapping *yaml.Node) map[string]int {
	stages := defaultStages
	if node := parser.FindKey(mapping, "stages"); node != nil && node.Kind == yaml.SequenceNode {
		var declared []string
		for _, s := range node.Content {
			if s.Kind == yaml.ScalarNode {
				declared = append(declared, s.Value)
			}
		}
		if len(declared) > 0 {
			stages = declared
		}
	}
	idx := make(map[string]int, len(stages))
	for i, s := range stages {
		idx[s] = i
	}
	return idx
}

func jobStageIndex(job *yaml.Node, stageIdx map[string]int) (int, bool) {
	stage := defaultStage
	if s := parser.FindKey(job, "stage"); s != nil && s.Kind == yaml.ScalarNode {
		stage = s.Value
	}
	i, ok := stageIdx[stage]
	return i, ok
}

func isProdDeployJob(job *yaml.Node) bool {
	env := parser.FindKey(job, "environment")
	if env == nil {
		return false
	}
	name := extractEnvName(env)
	return name != "" && isProdEnv(name)
}

func allowFailureFalse(job *yaml.Node) bool {
	af := parser.FindKey(job, "allow_failure")
	return af != nil && af.Kind == yaml.ScalarNode && af.Value == "false"
}

func isHiddenJob(name string) bool {
	return len(name) > 0 && name[0] == '.'
}
