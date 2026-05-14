package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl003 struct{}

var GL003 = &gl003{}

func (r *gl003) ID() string { return "GL003" }

// shaPattern matches a full or short commit SHA (8–40 hex chars).
var shaPattern = regexp.MustCompile(`^[0-9a-f]{8,40}$`)

// mutableRefs are branch names that are clearly mutable version pointers.
var mutableRefs = map[string]bool{
	"main": true, "master": true, "dev": true, "develop": true,
	"staging": true, "production": true, "latest": true, "HEAD": true,
	"nightly": true, "canary": true, "edge": true,
}

func (r *gl003) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	includeNode := parser.FindKey(mapping, "include")
	if includeNode == nil {
		return nil
	}

	// scalar shorthand (include: '/local/path.yml') is treated as local → safe
	if includeNode.Kind == yaml.ScalarNode {
		return nil
	}

	if includeNode.Kind != yaml.SequenceNode {
		return nil
	}

	var findings []finding.Finding
	for _, item := range includeNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		findings = append(findings, checkIncludeItem(item, file)...)
	}
	return findings
}

func checkIncludeItem(node *yaml.Node, file string) []finding.Finding {
	if parser.FindKey(node, "local") != nil || parser.FindKey(node, "template") != nil {
		return nil
	}

	if remote := parser.FindKey(node, "remote"); remote != nil {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("remote include %q — URL content is mutable and unverified; use a project include with a pinned ref instead", remote.Value),
			File:     file,
			Line:     remote.Line,
			Col:      remote.Column,
		}}
	}

	if component := parser.FindKey(node, "component"); component != nil {
		return checkComponentRef(component, file)
	}

	if project := parser.FindKey(node, "project"); project != nil {
		return checkProjectRef(node, project, file)
	}

	return nil
}

func checkProjectRef(node *yaml.Node, projectNode *yaml.Node, file string) []finding.Finding {
	refNode := parser.FindKey(node, "ref")
	if refNode == nil {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("project include %q missing \"ref\" — defaults to HEAD of default branch (mutable)", projectNode.Value),
			File:     file,
			Line:     projectNode.Line,
			Col:      projectNode.Column,
		}}
	}
	if isMutableRef(refNode.Value) {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("project include %q uses mutable ref %q — pin to a commit SHA or tag", projectNode.Value, refNode.Value),
			File:     file,
			Line:     refNode.Line,
			Col:      refNode.Column,
		}}
	}
	return nil
}

func checkComponentRef(node *yaml.Node, file string) []finding.Finding {
	// component refs follow the format: "gitlab.com/org/component@ref"
	at := strings.LastIndex(node.Value, "@")
	if at < 0 {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("component include %q missing version — add @<tag-or-sha>", node.Value),
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		}}
	}
	ref := node.Value[at+1:]
	if isMutableRef(ref) {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("component include %q uses mutable ref %q — pin to a tag or commit SHA", node.Value, ref),
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		}}
	}
	return nil
}

// isMutableRef returns true if the ref is a known mutable branch name.
// SHA-like strings are considered pinned; everything else (tags) is allowed.
func isMutableRef(ref string) bool {
	if shaPattern.MatchString(ref) {
		return false
	}
	return mutableRefs[ref]
}
