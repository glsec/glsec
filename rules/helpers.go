// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
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
	if env := parser.FindKey(job, "environment"); env != nil && !envActionNoDeploy(env) {
		return true
	}
	if deployLikeName(strings.ToLower(jobName), deployLikeKeywords) {
		return true
	}
	if stageNode := parser.FindKey(job, "stage"); stageNode != nil && stageNode.Kind == yaml.ScalarNode {
		return deployLikeName(strings.ToLower(stageNode.Value), deployLikeKeywords)
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

// IncludedOverride reports whether job can only be a partial override of a
// job from an included file (#978): the file has an include:, and neither the
// job nor a template it extends in this file has a script:, trigger: or run:.
// GitLab merges such a job into the included job of the same name, so a key
// it lacks here, such as rules:, may come from there.
func (in *Inheritance) IncludedOverride(job *yaml.Node) bool {
	if parser.FindKey(in.mapping, "include") == nil {
		return false
	}
	for _, key := range []string{"script", "trigger", "run"} {
		if in.Key(job, key) != nil {
			return false
		}
	}
	return true
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
		if def := parser.FindKey(in.mapping, "default"); def != nil {
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

// Chain returns the values of key along the job's extends: chain in this
// file, the job's own first, for keys GitLab deep-merges such as artifacts:
// and trigger:. default: is not included.
func (in *Inheritance) Chain(job *yaml.Node, key string) []*yaml.Node {
	var out []*yaml.Node
	in.chain(job, key, 0, map[*yaml.Node]bool{}, &out)
	return out
}

func (in *Inheritance) chain(job *yaml.Node, key string, depth int, seen map[*yaml.Node]bool, out *[]*yaml.Node) {
	if job == nil || job.Kind != yaml.MappingNode || seen[job] || depth > maxExtendsDepth {
		return
	}
	seen[job] = true
	if v := parser.FindKey(job, key); v != nil {
		*out = append(*out, v)
	}
	ext := parser.FindKey(job, "extends")
	if ext == nil {
		return
	}
	parents := []*yaml.Node{ext}
	if ext.Kind == yaml.SequenceNode {
		parents = ext.Content
	}
	for i := len(parents) - 1; i >= 0; i-- {
		if parents[i].Kind == yaml.ScalarNode {
			in.chain(in.jobs[parents[i].Value], key, depth+1, seen, out)
		}
	}
}

// Effective returns the job with what it inherits through extends: in this
// file merged in, the way GitLab merges it: mappings key by key and
// recursively, any other value replaced by the inheriting job's own; of
// several extends: entries the later one wins. default: is not merged in. A
// job without extends: is returned as is. Check ExtendsResolved first where a
// base in another file could change the answer.
func (in *Inheritance) Effective(job *yaml.Node) *yaml.Node {
	return in.effective(job, 0)
}

// effective has no seen set: the depth limit already bounds a cycle, and the
// common case, a job without extends:, then allocates nothing.
func (in *Inheritance) effective(job *yaml.Node, depth int) *yaml.Node {
	if job == nil || job.Kind != yaml.MappingNode || depth >= maxExtendsDepth {
		return job
	}
	ext := parser.FindKey(job, "extends")
	if ext == nil {
		return job
	}
	parents := []*yaml.Node{ext}
	if ext.Kind == yaml.SequenceNode {
		parents = ext.Content
	}
	var merged *yaml.Node
	for _, p := range parents {
		if base := in.jobs[p.Value]; p.Kind == yaml.ScalarNode && base != nil {
			merged = mergeMappings(merged, in.effective(base, depth+1))
		}
	}
	return mergeMappings(merged, job)
}

// Has reports whether the job or a template it extends in this file sets key.
// It allocates nothing, so a rule can call it before Effective to skip jobs
// that inherit nothing it looks at.
func (in *Inheritance) Has(job *yaml.Node, key string) bool {
	return in.has(job, key, 0)
}

func (in *Inheritance) has(job *yaml.Node, key string, depth int) bool {
	if job == nil || job.Kind != yaml.MappingNode || depth >= maxExtendsDepth {
		return false
	}
	if parser.FindKey(job, key) != nil {
		return true
	}
	ext := parser.FindKey(job, "extends")
	switch {
	case ext == nil:
		return false
	case ext.Kind == yaml.ScalarNode:
		return in.has(in.jobs[ext.Value], key, depth+1)
	}
	for _, p := range ext.Content {
		if p.Kind == yaml.ScalarNode && in.has(in.jobs[p.Value], key, depth+1) {
			return true
		}
	}
	return false
}

// mergeMappings returns over merged on top of base, without changing either.
func mergeMappings(base, over *yaml.Node) *yaml.Node {
	if base == nil || base.Kind != yaml.MappingNode || over.Kind != yaml.MappingNode {
		return over
	}
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: over.Tag, Line: over.Line, Column: over.Column}
	out.Content = make([]*yaml.Node, len(base.Content), len(base.Content)+len(over.Content))
	copy(out.Content, base.Content)
	n := len(base.Content)
	// A job has a few dozen keys at most: a linear search allocates nothing.
	for i := 0; i+1 < len(over.Content); i += 2 {
		k, v := over.Content[i], over.Content[i+1]
		j := 0
		for j+1 < n && out.Content[j].Value != k.Value {
			j += 2
		}
		if j+1 < n {
			out.Content[j] = k
			out.Content[j+1] = mergeMappings(out.Content[j+1], v)
			continue
		}
		out.Content = append(out.Content, k, v)
	}
	return out
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

// EachScriptBlock calls fn for every script sequence of the file: the
// top-level and default: before_script/after_script, each job's script,
// before_script, after_script and hooks, and run: step scripts. A sequence
// shared by several jobs through a YAML anchor is visited once, for the first
// job that uses it: a rule's result for it doesn't depend on the job, and the
// findings of the other jobs would only be merged by finding.Dedupe (#766).
// Rules whose result depends on the job use EachScriptBlockPerJob.
func EachScriptBlock(doc *yaml.Node, file string, fn func(node *yaml.Node, file, job string)) {
	seen := map[*yaml.Node]bool{}
	EachScriptBlockPerJob(doc, file, func(node *yaml.Node, file, job string) {
		if seen[node] {
			return
		}
		seen[node] = true
		fn(node, file, job)
	})
}

// nodeMemo caches a per-node result within one Check call, for rules that
// walk each job's lines and so meet a line shared through an anchor once per
// job (#766).
type nodeMemo[T any] map[*yaml.Node]T

func (m nodeMemo[T]) get(n *yaml.Node, f func() T) T {
	if v, ok := m[n]; ok {
		return v
	}
	v := f()
	m[n] = v
	return v
}

// EachScriptBlockPerJob is EachScriptBlock without the sharing shortcut: a
// sequence used by several jobs is visited once per job.
func EachScriptBlockPerJob(doc *yaml.Node, file string, fn func(node *yaml.Node, file, job string)) {
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

// EachScriptLinePerJob is EachScriptLine with every job visited, for rules
// whose result depends on the job.
func EachScriptLinePerJob(doc *yaml.Node, file string, fn func(line *yaml.Node, file, job string)) {
	EachScriptBlockPerJob(doc, file, func(node *yaml.Node, file, job string) {
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

// scriptMatchPos returns where to report a match that starts at byte off of
// a script item's value: the source line of the match, so a finding inside a
// `|` block points at its command (#974), and the item's column when the
// match is on the item's own line.
func scriptMatchPos(item *yaml.Node, off int) (line, col int) {
	line = parser.ScalarOffsetLine(item, off)
	if line == item.Line {
		col = item.Column
	}
	return line, col
}

// scriptLinePos is scriptMatchPos for the i-th line of a script item.
func scriptLinePos(item *yaml.Node, i int) (line, col int) {
	line = parser.ScalarContentLine(item, i)
	if line == item.Line {
		col = item.Column
	}
	return line, col
}

// fullSHARe matches a word that is exactly a full 40-character commit SHA.
var fullSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// dockerRunFlagFindings reports a warning on every script line whose docker
// run command passes the option flag matches, at the option: GL058, GL061 and
// GL077 differ only in the option and the message (#1078). Comment lines are
// skipped.
func dockerRunFlagFindings(doc *yaml.Node, file, ruleID string, flag *regexp.Regexp, message string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerRunRe.MatchString(v) || !flag.MatchString(v) {
			return
		}
		ln, col := scriptMatchPos(line, flag.FindStringIndex(v)[0])
		findings = append(findings, finding.Finding{
			RuleID:   ruleID,
			Severity: finding.Warn,
			Job:      job,
			Message:  message,
			File:     file,
			Line:     ln,
			Col:      col,
		})
	})
	return findings
}
