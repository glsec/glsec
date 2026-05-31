package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl067 struct{}

var GL067 = &gl067{}

func (r *gl067) ID() string { return "GL067" }

// officialAnalyzerRegistry is the host that GitLab's managed security templates
// pull their analyzer images from by default (via SECURE_ANALYZERS_PREFIX, which
// defaults to $CI_TEMPLATE_REGISTRY_HOST/security-products).
const officialAnalyzerRegistry = "registry.gitlab.com"

// analyzerImageVars are managed-scan controls that hold a full analyzer image
// reference. Repointing any of them off the official registry substitutes the
// scanner the same way SECURE_ANALYZERS_PREFIX does.
var analyzerImageVars = map[string]bool{
	"SAST_ANALYZER_IMAGE": true,
	"DS_ANALYZER_IMAGE":   true,
	"CS_ANALYZER_IMAGE":   true,
}

func (r *gl067) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, r.checkVariables(parser.FindKey(mapping, "variables"), file)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, r.checkVariables(parser.FindKey(def, "variables"), file)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range r.checkVariables(parser.FindKey(job, "variables"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func (r *gl067) checkVariables(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		isPrefix := key == "SECURE_ANALYZERS_PREFIX"
		if !isPrefix && !analyzerImageVars[key] {
			continue
		}

		scalar := analyzerScalar(node.Content[i+1])
		if scalar == nil {
			continue
		}
		host, off := analyzerOffOfficialRegistry(scalar.Value)
		if !off {
			continue
		}

		var msg string
		if isPrefix {
			msg = fmt.Sprintf("SECURE_ANALYZERS_PREFIX repoints managed-scan analyzers to registry %q instead of the default %s — every security-scan job would run an analyzer image from an unverified registry", host, officialAnalyzerRegistry)
		} else {
			msg = fmt.Sprintf("%s points the managed-scan analyzer image at registry %q instead of the default %s — the scan job would run an unverified analyzer image", key, host, officialAnalyzerRegistry)
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL067",
			Severity: finding.Warn,
			Message:  msg,
			File:     file,
			Line:     scalar.Line,
			Col:      scalar.Column,
		})
	}
	return findings
}

// analyzerScalar returns the scalar value node of a variable entry, unwrapping
// the extended form ({value: ..., description: ...}).
func analyzerScalar(val *yaml.Node) *yaml.Node {
	switch val.Kind {
	case yaml.ScalarNode:
		return val
	case yaml.MappingNode:
		if v := parser.FindKey(val, "value"); v != nil && v.Kind == yaml.ScalarNode {
			return v
		}
	}
	return nil
}

// analyzerOffOfficialRegistry reports the registry host of an analyzer prefix or
// image reference and whether it differs from the official GitLab registry. A
// host built from a variable expansion ($CI_TEMPLATE_REGISTRY_HOST/...) is not
// statically resolvable and is treated as default-equivalent.
func analyzerOffOfficialRegistry(ref string) (host string, off bool) {
	s := strings.TrimSpace(ref)
	if s == "" {
		return "", false
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	first := s
	if i := strings.Index(s, "/"); i >= 0 {
		first = s[:i]
	}
	if first == "" || strings.Contains(first, "$") {
		return "", false
	}
	host = strings.ToLower(first)
	return host, host != officialAnalyzerRegistry
}
