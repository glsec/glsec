package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl041 struct{}

var GL041 = &gl041{}

func (r *gl041) ID() string { return "GL041" }

var (
	// componentSHARe matches a full 40-character lowercase hex commit SHA.
	componentSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)

	// componentSemverRe matches a semver tag, optionally prefixed with "v".
	// Requires at least two dot-separated numeric segments (e.g. 1.0, v1.2.3).
	componentSemverRe = regexp.MustCompile(`^v?\d+\.\d+`)
)

func (r *gl041) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	includeNode := parser.FindKey(mapping, "include")
	if includeNode == nil || includeNode.Kind != yaml.SequenceNode {
		return nil
	}

	var findings []finding.Finding
	for _, item := range includeNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		component := parser.FindKey(item, "component")
		if component == nil {
			continue
		}
		if f := checkComponentVersion(component, file); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

func checkComponentVersion(node *yaml.Node, file string) *finding.Finding {
	val := node.Value
	at := strings.LastIndex(val, "@")
	if at < 0 {
		return &finding.Finding{
			RuleID:   "GL041",
			Severity: finding.Warn,
			Message:  fmt.Sprintf("component include %q has no version — add @<semver-tag> or @<sha> to pin it", val),
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		}
	}
	ref := val[at+1:]

	// Strip leading ~ (e.g. ~latest, ~1.0.0 — tilde prefix means "latest compatible" which is still mutable)
	if strings.HasPrefix(ref, "~") {
		return &finding.Finding{
			RuleID:   "GL041",
			Severity: finding.Warn,
			Message:  fmt.Sprintf("component include %q uses tilde version %q — pin to an exact semver tag or commit SHA", val, ref),
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		}
	}

	if componentSHARe.MatchString(ref) || componentSemverRe.MatchString(ref) {
		return nil
	}

	return &finding.Finding{
		RuleID:   "GL041",
		Severity: finding.Warn,
		Message:  fmt.Sprintf("component include %q uses mutable ref %q — pin to a semver tag (e.g. 1.0.0) or a full commit SHA", val, ref),
		File:     file,
		Line:     node.Line,
		Col:      node.Column,
	}
}
