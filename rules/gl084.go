package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl084 struct{}

var GL084 = &gl084{}

func (r *gl084) ID() string { return "GL084" }

// includeVarRe matches a CI variable reference anywhere in an include value,
// in both the $VAR and ${VAR} spellings.
var includeVarRe = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

// refNameVar is the one user-controlled variable GitLab resolves in an include
// section. Its value is the branch or tag name, chosen by whoever pushes.
const refNameVar = "CI_COMMIT_REF_NAME"

// serverControlledVarPrefixes and serverControlledVars are the predefined
// variables whose value the GitLab instance sets, not a pipeline caller. They
// are the documented way to write a portable include — the component reference
// $CI_SERVER_FQDN/$CI_PROJECT_PATH/my-component@1.0.0 is GitLab's own example —
// so they must never be flagged.
var serverControlledVarPrefixes = []string{"CI_PROJECT_", "CI_SERVER_", "CI_API_"}

var serverControlledVars = map[string]bool{
	"CI_PIPELINE_SOURCE":    true,
	"CI_PIPELINE_TRIGGERED": true,
	// Not resolvable in an include section, but its value is the project's
	// default branch, which no pipeline caller can set. Flagging it would be a
	// correctness complaint, not a security one.
	"CI_DEFAULT_BRANCH": true,
}

func serverControlled(name string) bool {
	if serverControlledVars[name] {
		return true
	}
	for _, p := range serverControlledVarPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (r *gl084) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	includeNode := parser.FindKey(mapping, "include")
	if includeNode == nil {
		return nil
	}

	var findings []finding.Finding
	switch includeNode.Kind {
	case yaml.ScalarNode:
		// include: '$TEMPLATE_PATH' is the local-include shorthand.
		findings = append(findings, checkIncludeField(includeNode, "local", file)...)
	case yaml.SequenceNode:
		for _, item := range includeNode.Content {
			switch item.Kind {
			case yaml.ScalarNode:
				findings = append(findings, checkIncludeField(item, "local", file)...)
			case yaml.MappingNode:
				findings = append(findings, checkIncludeVarItem(item, file)...)
			}
		}
	case yaml.MappingNode:
		findings = append(findings, checkIncludeVarItem(includeNode, file)...)
	}
	return findings
}

// checkIncludeVarItem inspects the location keys of one include entry.
//
// remote: is left to GL003, which already reports every remote include as an
// error; a second finding on the same line adds nothing. template: names a
// GitLab-shipped file and takes no variables. inputs: are passed to the
// included configuration, they do not select it.
func checkIncludeVarItem(node *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	for _, key := range []string{"local", "project", "ref", "file", "component"} {
		value := parser.FindKey(node, key)
		if value == nil {
			continue
		}
		switch value.Kind {
		case yaml.ScalarNode:
			findings = append(findings, checkIncludeField(value, key, file)...)
		case yaml.SequenceNode:
			// file: accepts a list of paths.
			for _, item := range value.Content {
				if item.Kind == yaml.ScalarNode {
					findings = append(findings, checkIncludeField(item, key, file)...)
				}
			}
		}
	}
	return findings
}

func checkIncludeField(node *yaml.Node, key, file string) []finding.Finding {
	value := node.Value
	if key == "component" {
		// The version after @ is GL041's business, not this rule's.
		if at := strings.LastIndex(value, "@"); at >= 0 {
			value = value[:at]
		}
	}

	varName := offendingIncludeVar(value)
	if varName == "" {
		return nil
	}

	severity := finding.Warn
	msg := fmt.Sprintf(
		"include %s: built from CI variable $%s — the included configuration is chosen when the pipeline starts (trigger, schedule or manual run), not in review; use a fixed value",
		key, varName,
	)
	if varName == refNameVar {
		severity = finding.Error
		msg = fmt.Sprintf(
			"include %s: built from $%s — the branch or tag name selects the included configuration, so anyone who can push a ref controls it; use a fixed path and a pinned ref",
			key, refNameVar,
		)
	}

	return []finding.Finding{{
		RuleID:   "GL084",
		Severity: severity,
		Message:  msg,
		File:     file,
		Line:     node.Line,
		Col:      node.Column,
	}}
}

// offendingIncludeVar returns the name of the variable to report for value, or
// the empty string when every reference in it is server-controlled.
// CI_COMMIT_REF_NAME wins over any other match because it carries the higher
// severity.
func offendingIncludeVar(value string) string {
	first := ""
	for _, m := range includeVarRe.FindAllStringSubmatch(value, -1) {
		name := m[1]
		if name == refNameVar {
			return name
		}
		if serverControlled(name) {
			continue
		}
		if first == "" {
			first = name
		}
	}
	return first
}
