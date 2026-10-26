// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// deployLikeKeywords covers job and stage names that indicate deployment,
// release, or artifact publishing activity.
var deployLikeKeywords = []string{
	"deploy", "release", "publish", "rollout",
	"migrat", "provision", "ship", "push", "upload", "dist",
}

// IsDeployLikeJob returns true when the job name, stage name, or presence of
// an environment: key indicates deployment, release, or artifact publishing.
// Used by rules that need to identify jobs that mutate external state.
func IsDeployLikeJob(jobName string, job *yaml.Node) bool {
	lower := strings.ToLower(jobName)
	for _, kw := range deployLikeKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	if parser.FindKey(job, "environment") != nil {
		return true
	}
	if stageNode := parser.FindKey(job, "stage"); stageNode != nil && stageNode.Kind == yaml.ScalarNode {
		stageLower := strings.ToLower(stageNode.Value)
		for _, kw := range deployLikeKeywords {
			if strings.Contains(stageLower, kw) {
				return true
			}
		}
	}
	return false
}

// windowsTagRe matches runner tags that select a Windows runner, such as
// windows, saas-windows-medium-amd64 or shared-windows.
var windowsTagRe = regexp.MustCompile(`(?i)\bwindows\b`)

// RunsOnWindows reports whether the job's runner tags select a Windows runner,
// where scripts run in PowerShell rather than a POSIX shell.
func (in *Inheritance) RunsOnWindows(job *yaml.Node) bool {
	tags := in.Key(job, "tags")
	if tags == nil || tags.Kind != yaml.SequenceNode {
		return false
	}
	for _, t := range tags.Content {
		if t.Kind == yaml.ScalarNode && windowsTagRe.MatchString(t.Value) {
			return true
		}
	}
	return false
}

// maxExtendsDepth is the number of extends: levels GitLab resolves.
// https://docs.gitlab.com/ci/yaml/#extends
const maxExtendsDepth = 11

// Inheritance resolves the keys a job inherits within one file. It indexes the
// top-level keys once, so following extends: chains stays cheap however many
// jobs the file has.
type Inheritance struct {
	mapping *yaml.Node
	jobs    map[string]*yaml.Node
}

func NewInheritance(doc *yaml.Node) *Inheritance {
	mapping := parser.Unwrap(doc)
	in := &Inheritance{mapping: mapping, jobs: map[string]*yaml.Node{}}
	if mapping.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(mapping.Content); i += 2 {
			name := mapping.Content[i].Value
			if _, ok := in.jobs[name]; !ok {
				in.jobs[name] = mapping.Content[i+1]
			}
		}
	}
	return in
}

// Key returns the value of key that applies to job: its own, else from the
// jobs it extends in the same file (later entries of an extends: list override
// earlier ones), else from default:, else from the top-level
// before_script:/after_script:. Jobs in included files are not followed.
func (in *Inheritance) Key(job *yaml.Node, key string) *yaml.Node {
	if v := in.extendedKey(job, key, 0, map[*yaml.Node]bool{}); v != nil {
		return v
	}
	if inheritsDefault(job, key) {
		if def := in.jobs["default"]; def != nil {
			if v := parser.FindKey(def, key); v != nil {
				return v
			}
		}
		if key == "before_script" || key == "after_script" {
			return in.jobs[key]
		}
	}
	return nil
}

func (in *Inheritance) extendedKey(job *yaml.Node, key string, depth int, seen map[*yaml.Node]bool) *yaml.Node {
	if job == nil || job.Kind != yaml.MappingNode || seen[job] {
		return nil
	}
	seen[job] = true
	if v := parser.FindKey(job, key); v != nil {
		return v
	}
	ext := parser.FindKey(job, "extends")
	if ext == nil || depth >= maxExtendsDepth {
		return nil
	}
	parents := []*yaml.Node{ext}
	if ext.Kind == yaml.SequenceNode {
		parents = ext.Content
	}
	for i := len(parents) - 1; i >= 0; i-- {
		if parents[i].Kind != yaml.ScalarNode {
			continue
		}
		if v := in.extendedKey(in.jobs[parents[i].Value], key, depth+1, seen); v != nil {
			return v
		}
	}
	return nil
}

// ExtendsResolved reports whether every job in the job's extends: chain is
// defined in this file, so Key sees everything the job inherits.
func (in *Inheritance) ExtendsResolved(job *yaml.Node) bool {
	return in.extendsResolved(job, 0, map[*yaml.Node]bool{})
}

func (in *Inheritance) extendsResolved(job *yaml.Node, depth int, seen map[*yaml.Node]bool) bool {
	if job == nil || job.Kind != yaml.MappingNode || seen[job] || depth >= maxExtendsDepth {
		return true
	}
	seen[job] = true
	ext := parser.FindKey(job, "extends")
	if ext == nil {
		return true
	}
	parents := []*yaml.Node{ext}
	if ext.Kind == yaml.SequenceNode {
		parents = ext.Content
	}
	for _, p := range parents {
		base, ok := in.jobs[p.Value]
		if p.Kind != yaml.ScalarNode || !ok || !in.extendsResolved(base, depth+1, seen) {
			return false
		}
	}
	return true
}

// inheritsDefault reports whether the job takes key from default:.
// inherit: default: false opts out of all keys, a list opts in to the keys it names.
func inheritsDefault(job *yaml.Node, key string) bool {
	inherit := parser.FindKey(job, "inherit")
	if inherit == nil {
		return true
	}
	d := parser.FindKey(inherit, "default")
	switch {
	case d == nil:
		return true
	case d.Kind == yaml.ScalarNode:
		return d.Value != "false"
	case d.Kind == yaml.SequenceNode:
		for _, k := range d.Content {
			if k.Value == key {
				return true
			}
		}
		return false
	}
	return true
}

// hookScriptNode returns the hooks:pre_get_sources_script sequence node for a
// job or default: mapping, or nil. These commands run on the runner before the
// repository is cloned, so they are script lines that security rules must scan.
func hookScriptNode(container *yaml.Node) *yaml.Node {
	hooks := parser.FindKey(container, "hooks")
	if hooks == nil {
		return nil
	}
	return parser.FindKey(hooks, "pre_get_sources_script")
}

// isScriptList reports whether n is a script list whose items are commands: a
// sequence that isn't an unresolved !reference, whose items would be its path.
func isScriptList(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.SequenceNode && !parser.IsReference(n)
}

// CollectJobScriptLines returns all scalar script lines from a job's
// before_script, script, after_script, and hooks:pre_get_sources_script sections.
func CollectJobScriptLines(job *yaml.Node) []*yaml.Node {
	var lines []*yaml.Node
	appendScalars := func(node *yaml.Node) {
		if !isScriptList(node) {
			return
		}
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				lines = append(lines, item)
			}
		}
	}
	for _, key := range []string{"before_script", "script", "after_script"} {
		appendScalars(parser.FindKey(job, key))
	}
	appendScalars(hookScriptNode(job))
	lines = append(lines, parser.RunStepScripts(job)...)
	return lines
}

// EachScriptBlock visits every script *sequence node* in the document: global
// before/after_script, default: before/after_script + hooks:pre_get_sources_script,
// and each job's script/before_script/after_script + hooks:pre_get_sources_script.
// fn receives the sequence node, the file path, and the job name (empty for
// global and default: blocks). hooks: is not a valid top-level keyword, so it is
// only visited under default: and jobs.
func EachScriptBlock(doc *yaml.Node, file string, fn func(node *yaml.Node, file, job string)) {
	mapping := parser.Unwrap(doc)

	visit := func(node *yaml.Node, job string) {
		if isScriptList(node) {
			fn(node, file, job)
		}
	}

	for _, key := range []string{"before_script", "after_script"} {
		visit(parser.FindKey(mapping, key), "")
	}

	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			visit(parser.FindKey(def, key), "")
		}
		visit(hookScriptNode(def), "")
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			visit(parser.FindKey(job, key), name.Value)
		}
		visit(hookScriptNode(job), name.Value)
		for _, block := range parser.RunStepBlocks(job) {
			fn(block, file, name.Value)
		}
	})
}

// EachScriptLine visits every scalar script line in the document, calling fn
// for each. It covers the same blocks as EachScriptBlock (global, default:, and
// per-job script sections, including hooks:pre_get_sources_script).
// fn receives the line node, the file path, and the job name (empty for
// global and default: sections).
func EachScriptLine(doc *yaml.Node, file string, fn func(line *yaml.Node, file, job string)) {
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				fn(item, file, job)
			}
		}
	})
}

// eachVariablesBlock visits every variables: mapping whose values GitLab can
// apply: top-level, default:, each workflow:rules entry, and per job its own
// variables: and each of its rules: entries (#672). A value moved from
// variables: into a rule is committed in the file all the same. fn receives the
// block, the job name (empty for pipeline-level blocks) and the rules: entry
// the block belongs to (nil for plain variables:).
func eachVariablesBlock(doc *yaml.Node, fn func(vars *yaml.Node, job string, rule *yaml.Node)) {
	mapping := parser.Unwrap(doc)
	fn(parser.FindKey(mapping, "variables"), "", nil)
	if def := parser.FindKey(mapping, "default"); def != nil {
		fn(parser.FindKey(def, "variables"), "", nil)
	}
	if workflow := parser.FindKey(mapping, "workflow"); workflow != nil {
		eachRuleVariables(workflow, func(vars, rule *yaml.Node) { fn(vars, "", rule) })
	}
	parser.EachJob(doc, func(name, job *yaml.Node) {
		fn(parser.FindKey(job, "variables"), name.Value, nil)
		eachRuleVariables(job, func(vars, rule *yaml.Node) { fn(vars, name.Value, rule) })
	})
}

// eachRuleVariables calls fn for the variables: of each rules: entry of a job
// or of workflow:.
func eachRuleVariables(container *yaml.Node, fn func(vars, rule *yaml.Node)) {
	rules := parser.FindKey(container, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return
	}
	for _, rule := range rules.Content {
		if rule.Kind != yaml.MappingNode {
			continue
		}
		if vars := parser.FindKey(rule, "variables"); vars != nil {
			fn(vars, rule)
		}
	}
}
