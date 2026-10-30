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

type gl037 struct{}

var GL037 = &gl037{}

func (r *gl037) ID() string { return "GL037" }

func (r *gl037) Check(doc *yaml.Node, file string) []finding.Finding {
	// Only flag when a pipeline-level block (top-level variables: or a
	// workflow:rules entry) has at least one secret-like name.
	secrets := map[string]bool{}
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		if job == "" {
			collectForwardedSecrets(vars, secrets)
		}
	})
	if len(secrets) == 0 {
		return nil
	}

	in := NewInheritance(doc)
	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// A hidden job is a template: the jobs that extend or merge it are
		// reported, with what they inherit.
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		if !in.Has(job, "trigger") {
			return
		}
		job = in.Effective(job)
		trigger := parser.FindKey(job, "trigger")
		if trigger == nil {
			return
		}
		// A child pipeline (trigger: include:) runs in the same project; only
		// a multi-project trigger hands the variables to another project.
		if trigger.Kind == yaml.MappingNode && parser.FindKey(trigger, "project") == nil {
			return
		}
		if !inheritsAnyOf(parser.FindKey(job, "inherit"), secrets) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL037",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "trigger: job has no inherit: variables: false — top-level secret variables are implicitly forwarded to the downstream pipeline; add inherit: variables: false and pass only what the downstream needs",
			File:     file,
			Line:     name.Line,
			Col:      name.Column,
		})
	})
	return findings
}

// collectForwardedSecrets adds the secret-named variables of a block whose
// value comes from another, non-predefined variable: a CI/CD setting that the
// file passes on. A literal value is in the repository already, and a
// predefined variable is in every pipeline anyway, so forwarding either
// exposes nothing new.
func collectForwardedSecrets(node *yaml.Node, out map[string]bool) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		name := node.Content[i].Value
		if !hasSecretSuffix(name) || nonSecretSuffixRe.MatchString(strings.ToUpper(name)) {
			continue
		}
		val := resolveScalar(node.Content[i+1])
		if val == nil {
			continue
		}
		for _, m := range secretRefRe.FindAllStringSubmatch(val.Value, -1) {
			if !isPredefinedVar(m[1]) {
				out[name] = true
				break
			}
		}
	}
}

// secretRefRe matches a variable reference; group 1 is the name.
var secretRefRe = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)

// inheritsAnyOf reports whether a trigger job receives any of the named
// top-level variables: inherit: variables: false receives none, a list only
// the names it lists.
func inheritsAnyOf(inherit *yaml.Node, names map[string]bool) bool {
	if inherit == nil || inherit.Kind != yaml.MappingNode {
		return true
	}
	v := parser.FindKey(inherit, "variables")
	switch {
	case v == nil:
		return true
	case v.Kind == yaml.ScalarNode:
		return v.Value != "false"
	case v.Kind == yaml.SequenceNode:
		for _, n := range v.Content {
			if names[n.Value] {
				return true
			}
		}
		return false
	}
	return true
}
