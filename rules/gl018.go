package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl018 struct{}

var GL018 = &gl018{}

func (r *gl018) ID() string { return "GL018" }

// secretNameSuffixes identifies variable names that suggest secret content.
var secretNameSuffixes = []string{
	"_TOKEN", "_SECRET", "_PASSWORD", "_PASSWD", "_PASS", "_PWD",
	"_KEY", "_CREDENTIAL", "_CERT",
}

// varRefRe matches a value that is (or starts with) a CI variable reference.
var varRefRe = regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)

func (r *gl018) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)

	var findings []finding.Finding

	if varsNode := parser.FindKey(mapping, "variables"); varsNode != nil && varsNode.Kind == yaml.MappingNode {
		findings = append(findings, checkSecretReexport(varsNode, file)...)
	}

	if def := parser.FindKey(mapping, "default"); def != nil {
		if varsNode := parser.FindKey(def, "variables"); varsNode != nil && varsNode.Kind == yaml.MappingNode {
			findings = append(findings, checkSecretReexport(varsNode, file)...)
		}
	}

	return findings
}

func checkSecretReexport(varsNode *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	for i := 0; i+1 < len(varsNode.Content); i += 2 {
		nameNode := varsNode.Content[i]
		valNode := varsNode.Content[i+1]

		if !hasSecretSuffix(nameNode.Value) {
			continue
		}

		// Resolve value: scalar or extended {value: ..., description: ...} form.
		scalar := resolveScalar(valNode)
		if scalar == nil || !varRefRe.MatchString(scalar.Value) {
			continue
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL018",
			Severity: finding.Warn,
			Message: fmt.Sprintf(
				"secret variable %q re-exported at pipeline level from %s — available to all jobs including untrusted ones; scope it to specific jobs or use GitLab Settings environment scoping",
				nameNode.Value, scalar.Value,
			),
			File: file,
			Line: nameNode.Line,
			Col:  nameNode.Column,
		})
	}
	return findings
}

func hasSecretSuffix(name string) bool {
	upper := strings.ToUpper(name)
	for _, suffix := range secretNameSuffixes {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	return false
}

func resolveScalar(node *yaml.Node) *yaml.Node {
	switch node.Kind {
	case yaml.ScalarNode:
		return node
	case yaml.MappingNode:
		if v := parser.FindKey(node, "value"); v != nil && v.Kind == yaml.ScalarNode {
			return v
		}
	}
	return nil
}
