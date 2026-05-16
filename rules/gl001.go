package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl001 struct{}

var GL001 = &gl001{}

func (r *gl001) ID() string { return "GL001" }

func (r *gl001) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkImageNode(parser.FindKey(mapping, "image"), file)...)
	findings = append(findings, checkServicesNode(parser.FindKey(mapping, "services"), file)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkImageNode(parser.FindKey(def, "image"), file)...)
		findings = append(findings, checkServicesNode(parser.FindKey(def, "services"), file)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range checkImageNode(parser.FindKey(job, "image"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
		for _, f := range checkServicesNode(parser.FindKey(job, "services"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

// mutableTags is the set of well-known mutable image tags.
var mutableTags = map[string]bool{
	"latest":    true,
	"stable":    true,
	"edge":      true,
	"dev":       true,
	"main":      true,
	"master":    true,
	"nightly":   true,
	"rolling":   true,
	"canary":    true,
	"beta":      true,
	"alpha":     true,
	"lts":       true,
	"current":   true,
	"testing":   true,
	"oldstable": true,
}

func checkImageNode(node *yaml.Node, file string) []finding.Finding {
	if node == nil {
		return nil
	}
	ref, line, col := imageRef(node)
	if ref == "" {
		return nil
	}
	return checkRef(ref, line, col, file)
}

func checkServicesNode(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		ref, line, col := imageRef(item)
		if ref == "" {
			continue
		}
		findings = append(findings, checkRef(ref, line, col, file)...)
	}
	return findings
}

// imageRef extracts the image reference and source location from a node.
// Handles both scalar ("node:latest") and mapping ({name: node:latest}) forms.
func imageRef(node *yaml.Node) (ref string, line, col int) {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value, node.Line, node.Column
	case yaml.MappingNode:
		_, val := parser.FindKeyNode(node, "name")
		if val != nil {
			return val.Value, val.Line, val.Column
		}
	}
	return "", 0, 0
}

// isVarRef reports whether ref is entirely a shell variable expression
// ($MY_IMAGE or ${MY_IMAGE}). Such refs cannot be statically analysed
// for tag presence and must not be flagged as "no tag".
func isVarRef(ref string) bool {
	if len(ref) == 0 || ref[0] != '$' {
		return false
	}
	rest := ref[1:]
	if len(rest) > 0 && rest[0] == '{' {
		rest = strings.TrimSuffix(rest, "}")
		rest = rest[1:]
	}
	for _, ch := range rest {
		if (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}
	return len(rest) > 0
}

func checkRef(ref string, line, col int, file string) []finding.Finding {
	if strings.Contains(ref, "@sha256:") {
		return nil
	}
	if isVarRef(ref) {
		return nil
	}
	tag := imageTag(ref)
	if tag == "" {
		return []finding.Finding{{
			RuleID:   "GL001",
			Severity: finding.Error,
			Message:  fmt.Sprintf("image %q has no tag — defaults to latest (mutable)", ref),
			File:     file, Line: line, Col: col,
		}}
	}
	if mutableTags[tag] {
		return []finding.Finding{{
			RuleID:   "GL001",
			Severity: finding.Error,
			Message:  fmt.Sprintf("image %q uses mutable tag %q — pin to a specific version or digest", ref, tag),
			File:     file, Line: line, Col: col,
		}}
	}
	return nil
}

// imageTag extracts the tag from an image reference.
// Returns empty string if no tag is present (implying latest).
func imageTag(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ""
	}
	last := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		last = ref[i+1:]
	}
	if i := strings.Index(last, ":"); i >= 0 {
		return last[i+1:]
	}
	return ""
}
