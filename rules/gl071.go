package rules

import (
	"fmt"

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

	// Highest stage index that contains a production-like deploy job.
	maxDeployIdx := -1
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if isHiddenJob(name.Value) || !isProdDeployJob(job) {
			return
		}
		if idx, ok := jobStageIndex(job, stageIdx); ok && idx > maxDeployIdx {
			maxDeployIdx = idx
		}
	})
	if maxDeployIdx < 0 {
		return nil
	}

	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if isHiddenJob(name.Value) {
			return
		}
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
		if !ok || idx >= maxDeployIdx {
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
