// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl051 struct{}

var GL051 = &gl051{}

func (r *gl051) ID() string { return "GL051" }

// Check handles the single-document form, where spec: sits next to the jobs.
func (r *gl051) Check(doc *yaml.Node, file string) []finding.Finding {
	return r.CheckWithSpec(doc, doc, file)
}

// CheckWithSpec reads the input declarations from spec and their uses from doc.
func (r *gl051) CheckWithSpec(spec, doc *yaml.Node, file string) []finding.Finding {
	findings := gl051SpecInputs(spec, doc, file)
	in := NewInheritance(doc)
	parser.EachJob(doc, func(name, job *yaml.Node) {
		if in.Has(job, "inputs") {
			findings = append(findings, gl051JobInputs(name.Value, in.Effective(job), file)...)
		}
	})
	return findings
}

// gl051SpecInputs checks spec:inputs interpolated with $[[ inputs.NAME ]].
func gl051SpecInputs(spec, doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)

	unconstrained := gl051UnconstrainedInputs(parser.Unwrap(spec))
	if len(unconstrained) == 0 {
		return nil
	}

	patterns := make([]gl051Input, 0, len(unconstrained))
	for _, name := range unconstrained {
		patterns = append(patterns, gl051Input{name, regexp.MustCompile(`\$\[\[\s*inputs\.` + regexp.QuoteMeta(name) + gl051Accessors + `\s*(\|[^\]]*)?\]\]`)})
	}

	var findings []finding.Finding

	findings = append(findings, gl051CheckImage(parser.FindKey(mapping, "image"), file, "", patterns)...)
	findings = append(findings, gl051CheckServices(parser.FindKey(mapping, "services"), file, "", patterns)...)
	for _, key := range []string{"before_script", "after_script"} {
		findings = append(findings, gl051CheckScripts(parser.FindKey(mapping, key), file, "", key, patterns)...)
	}

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, gl051CheckImage(parser.FindKey(def, "image"), file, "", patterns)...)
		findings = append(findings, gl051CheckServices(parser.FindKey(def, "services"), file, "", patterns)...)
		for _, key := range []string{"before_script", "after_script"} {
			findings = append(findings, gl051CheckScripts(parser.FindKey(def, key), file, "", key, patterns)...)
		}
		findings = append(findings, gl051CheckScripts(hookScriptNode(def), file, "", "hooks:pre_get_sources_script", patterns)...)
	}

	parser.EachJob(doc, func(nameNode *yaml.Node, jobNode *yaml.Node) {
		job := nameNode.Value
		findings = append(findings, gl051CheckImage(parser.FindKey(jobNode, "image"), file, job, patterns)...)
		findings = append(findings, gl051CheckServices(parser.FindKey(jobNode, "services"), file, job, patterns)...)
		for _, key := range []string{"script", "before_script", "after_script"} {
			findings = append(findings, gl051CheckScripts(parser.FindKey(jobNode, key), file, job, key, patterns)...)
		}
		for _, block := range parser.RunStepBlocks(jobNode) {
			findings = append(findings, gl051CheckScripts(block, file, job, "run", patterns)...)
		}
		findings = append(findings, gl051CheckScripts(hookScriptNode(jobNode), file, job, "hooks:pre_get_sources_script", patterns)...)
		findings = append(findings, gl051CheckEnvironment(parser.FindKey(jobNode, "environment"), file, job, patterns)...)
	})

	return findings
}

// gl051Input is an unconstrained input and the pattern of its interpolation.
// They are kept in the order spec:inputs declares them, so findings on one
// line come out in the same order on every run (#1081).
type gl051Input struct {
	name string
	re   *regexp.Regexp
}

// gl051Accessors matches array indexing and nested keys after an input name,
// as in $[[ inputs.servers[0].host ]].
const gl051Accessors = `(?:\[\d+\]|\.[A-Za-z0-9_-]+)*`

// gl051UnconstrainedInputs returns spec:inputs names whose values a caller can
// choose freely.
func gl051UnconstrainedInputs(mapping *yaml.Node) []string {
	spec := parser.FindKey(mapping, "spec")
	if spec == nil {
		return nil
	}
	inputs := parser.FindKey(spec, "inputs")
	if inputs == nil || inputs.Kind != yaml.MappingNode {
		return nil
	}
	var unconstrained []string
	for i := 0; i+1 < len(inputs.Content); i += 2 {
		if !gl051Constrained(inputs.Content[i+1]) {
			unconstrained = append(unconstrained, inputs.Content[i].Value)
		}
	}
	return unconstrained
}

// gl051Constrained reports whether GitLab restricts an input's value: an
// options: allowlist or a regex:, a number or boolean type, or spec:inputs:rules
// where every entry carries options:. A rules entry without options: (such as
// default: null) lets the user type any value.
func gl051Constrained(def *yaml.Node) bool {
	if def.Kind != yaml.MappingNode {
		return false
	}
	if parser.FindKey(def, "regex") != nil || parser.FindKey(def, "options") != nil {
		return true
	}
	if t := parser.FindKey(def, "type"); t != nil && (t.Value == "number" || t.Value == "boolean") {
		return true
	}
	rules := parser.FindKey(def, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode || len(rules.Content) == 0 {
		return false
	}
	for _, entry := range rules.Content {
		if entry.Kind != yaml.MappingNode || parser.FindKey(entry, "options") == nil {
			return false
		}
	}
	return true
}

func gl051CheckScalar(node *yaml.Node, file, job, keyword string, patterns []gl051Input) []finding.Finding {
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}
	var findings []finding.Finding
	for _, in := range patterns {
		inputName := in.name
		m := in.re.FindString(node.Value)
		if m == "" {
			continue
		}
		msg := fmt.Sprintf("unconstrained spec:inputs entry %q interpolated into %s — add regex:, options:, or a number/boolean type: to restrict caller-supplied values", inputName, keyword)
		if strings.Contains(m, "posix_escape") {
			msg += " (posix_escape is not a security control for untrusted input)"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL051",
			Severity: finding.Warn,
			Job:      job,
			Message:  msg,
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		})
	}
	return findings
}

func gl051CheckImage(node *yaml.Node, file, job string, patterns []gl051Input) []finding.Finding {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return gl051CheckScalar(node, file, job, "image:", patterns)
	case yaml.MappingNode:
		return gl051CheckScalar(parser.FindKey(node, "name"), file, job, "image:", patterns)
	}
	return nil
}

func gl051CheckServices(node *yaml.Node, file, job string, patterns []gl051Input) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			findings = append(findings, gl051CheckScalar(item, file, job, "services:", patterns)...)
		case yaml.MappingNode:
			findings = append(findings, gl051CheckScalar(parser.FindKey(item, "name"), file, job, "services:", patterns)...)
		}
	}
	return findings
}

func gl051CheckScripts(node *yaml.Node, file, job, keyword string, patterns []gl051Input) []finding.Finding {
	if !isScriptList(node) {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		findings = append(findings, gl051CheckScalar(item, file, job, keyword+":", patterns)...)
	}
	return findings
}

func gl051CheckEnvironment(node *yaml.Node, file, job string, patterns []gl051Input) []finding.Finding {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return gl051CheckScalar(node, file, job, "environment:name:", patterns)
	case yaml.MappingNode:
		return gl051CheckScalar(parser.FindKey(node, "name"), file, job, "environment:name:", patterns)
	}
	return nil
}

// gl051JobKeywords are the job keywords GitLab interpolates job inputs into.
var gl051JobKeywords = []string{"script", "before_script", "after_script", "image", "services", "cache", "artifacts"}

// gl051JobInputs checks a job's own inputs:, referenced as ${{ job.inputs.NAME }}.
// Whoever can run the job manually, or retry it with modified values, sets
// them, and GitLab substitutes the text before the shell runs, so quoting in
// the script does not help.
func gl051JobInputs(jobName string, job *yaml.Node, file string) []finding.Finding {
	inputs := parser.FindKey(job, "inputs")
	if inputs == nil || inputs.Kind != yaml.MappingNode {
		return nil
	}
	var names []string
	patterns := map[string]*regexp.Regexp{}
	for i := 0; i+1 < len(inputs.Content); i += 2 {
		if name := inputs.Content[i].Value; !gl051Constrained(inputs.Content[i+1]) {
			names = append(names, name)
			patterns[name] = regexp.MustCompile(`\$\{\{[^}]*\bjob\.inputs\.` + regexp.QuoteMeta(name) + `(?:[^A-Za-z0-9_-][^}]*)?\}\}`)
		}
	}
	if len(patterns) == 0 {
		return nil
	}
	severity := finding.Warn
	if IsDeployLikeJob(jobName, job) {
		severity = finding.Error
	}
	var findings []finding.Finding
	for _, key := range gl051JobKeywords {
		eachScalar(parser.FindKey(job, key), func(node *yaml.Node) {
			for _, name := range names {
				if !patterns[name].MatchString(node.Value) {
					continue
				}
				findings = append(findings, finding.Finding{
					RuleID:   "GL051",
					Severity: severity,
					Job:      jobName,
					Message:  fmt.Sprintf("unconstrained job input %q interpolated into %s: — anyone who can run or retry the job sets its value, and GitLab substitutes it before the shell runs; add options:, regex:, or a number/boolean type:", name, key),
					File:     file,
					Line:     node.Line,
					Col:      node.Column,
				})
			}
		})
	}
	return findings
}

// eachScalar calls fn for every scalar under node.
func eachScalar(node *yaml.Node, fn func(*yaml.Node)) {
	if node == nil || parser.IsReference(node) {
		return
	}
	if node.Kind == yaml.ScalarNode {
		fn(node)
		return
	}
	for _, child := range node.Content {
		eachScalar(child, fn)
	}
}
