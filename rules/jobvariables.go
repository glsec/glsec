// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// pipelineVariables are the variables: that apply to every job: the top-level
// and default: blocks, nearest first, and those of the workflow:rules entries.
type pipelineVariables struct {
	blocks   []*yaml.Node
	workflow *yaml.Node
}

func pipelineVariablesOf(doc *yaml.Node) pipelineVariables {
	mapping := parser.Unwrap(doc)
	p := pipelineVariables{workflow: parser.FindKey(mapping, "workflow")}
	if v := parser.FindKey(mapping, "variables"); v != nil {
		p.blocks = append(p.blocks, v)
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		if v := parser.FindKey(def, "variables"); v != nil {
			p.blocks = append(p.blocks, v)
		}
	}
	return p
}

// jobVariables answers what value a variable can have in one job (#1165).
type jobVariables struct {
	// job has the variables: and rules: GitLab sees after merging extends:.
	job      *yaml.Node
	pipeline pipelineVariables
	inherit  *yaml.Node
}

func variablesOf(in *Inheritance, job *yaml.Node, pipeline pipelineVariables) jobVariables {
	return jobVariables{in.Effective(job), pipeline, in.inheritValue(job, "variables")}
}

// possible returns the values name can have in the job, nearest first, and
// whether it can also be unset. A rules: entry applies only when it matches,
// so its value overrides without replacing, unless every entry that runs the
// job sets the name. The job's variables: override the pipeline's, and
// workflow:rules override the top level the same way rules: do.
func (v jobVariables) possible(name string) (values []string, unset bool) {
	values, all := ruleVariableValues(v.job, name)
	if all {
		return values, false
	}
	if own := varValues(parser.FindKey(v.job, "variables"), name); own != nil {
		return append(values, own...), false
	}
	if !inheritAllows(v.inherit, name) {
		return values, true
	}
	workflow, all := ruleVariableValues(v.pipeline.workflow, name)
	values = append(values, workflow...)
	if all {
		return values, false
	}
	for _, block := range v.pipeline.blocks {
		if global := varValues(block, name); global != nil {
			return append(values, global...), false
		}
	}
	return values, true
}

// ruleVariableValues returns what the rules: entries of container set for
// name, and whether every entry that can run it does.
func ruleVariableValues(container *yaml.Node, name string) (values []string, all bool) {
	if container == nil {
		return nil, false
	}
	rules := parser.FindKey(container, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return nil, false
	}
	all = true
	running := false
	for _, rule := range rules.Content {
		if rule.Kind == yaml.MappingNode {
			if when := parser.FindKey(rule, "when"); when != nil && when.Value == "never" {
				continue
			}
		}
		running = true
		var set []string
		if rule.Kind == yaml.MappingNode {
			set = varValues(parser.FindKey(rule, "variables"), name)
		}
		if set == nil {
			all = false
		}
		values = append(values, set...)
	}
	return values, all && running
}

// always reports whether every value name can have satisfies want, so that a
// protection holds on each path through the job.
func (v jobVariables) always(name string, want func(string) bool) bool {
	values, unset := v.possible(name)
	if unset || len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !want(value) {
			return false
		}
	}
	return true
}

// sometimes reports whether some value name can have satisfies want.
func (v jobVariables) sometimes(name string, want func(string) bool) bool {
	values, _ := v.possible(name)
	for _, value := range values {
		if want(value) {
			return true
		}
	}
	return false
}

// isTrueValue reports a variable set to true, as a string or a YAML boolean.
func isTrueValue(v string) bool { return strings.EqualFold(v, "true") }

// isSetValue reports a variable with a non-empty value.
func isSetValue(v string) bool { return strings.TrimSpace(v) != "" }
