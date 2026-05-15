package rules

import (
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl031 struct{}

var GL031 = &gl031{}

func (r *gl031) ID() string { return "GL031" }

func (r *gl031) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	if f := checkDockerTLS(parser.FindKey(mapping, "variables"), file, ""); f != nil {
		findings = append(findings, *f)
	}

	if def := parser.FindKey(mapping, "default"); def != nil {
		if f := checkDockerTLS(parser.FindKey(def, "variables"), file, ""); f != nil {
			findings = append(findings, *f)
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if f := checkDockerTLS(parser.FindKey(job, "variables"), file, name.Value); f != nil {
			findings = append(findings, *f)
		}
	})

	return findings
}

func checkDockerTLS(node *yaml.Node, file, job string) *finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		if key.Value != "DOCKER_TLS_CERTDIR" {
			continue
		}
		scalar := resolveScalar(val)
		if scalar == nil || scalar.Value != "" {
			continue
		}
		f := finding.Finding{
			RuleID:   "GL031",
			Severity: finding.Error,
			Job:      job,
			Message:  "DOCKER_TLS_CERTDIR set to empty string — disables TLS on the Docker daemon (port 2375), exposing it to any process on the runner network; set it to \"/certs\" and use port 2376",
			File:     file,
			Line:     key.Line,
			Col:      key.Column,
		}
		return &f
	}
	return nil
}
