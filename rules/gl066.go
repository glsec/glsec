package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl066 struct{}

var GL066 = &gl066{}

func (r *gl066) ID() string { return "GL066" }

// dockerAuthKeyRe matches the JSON "auths"/"auth" key of an inline Docker
// registry credential document.
var dockerAuthKeyRe = regexp.MustCompile(`"auths?"\s*:`)

func (r *gl066) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkDockerAuthConfig(parser.FindKey(mapping, "variables"), file)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkDockerAuthConfig(parser.FindKey(def, "variables"), file)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range checkDockerAuthConfig(parser.FindKey(job, "variables"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func checkDockerAuthConfig(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value != "DOCKER_AUTH_CONFIG" {
			continue
		}

		val := node.Content[i+1]
		var scalar *yaml.Node
		switch val.Kind {
		case yaml.ScalarNode:
			scalar = val
		case yaml.MappingNode:
			// Extended form: {value: ..., description: ...}
			if v := parser.FindKey(val, "value"); v != nil && v.Kind == yaml.ScalarNode {
				scalar = v
			}
		}
		if scalar == nil {
			continue
		}

		v := strings.TrimSpace(scalar.Value)
		// A whole-value variable reference ($REGISTRY_AUTH) is the safe form.
		if v == "" || strings.HasPrefix(v, "$") {
			continue
		}
		if !dockerAuthKeyRe.MatchString(v) {
			continue
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL066",
			Severity: finding.Error,
			Message:  "DOCKER_AUTH_CONFIG contains inline registry credentials (\"auth\" is base64, not encryption) — store it as a masked, protected CI/CD variable (Settings → CI/CD → Variables) instead",
			File:     file,
			Line:     scalar.Line,
			Col:      scalar.Column,
		})
	}
	return findings
}
