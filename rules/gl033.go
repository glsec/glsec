package rules

import (
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl033 struct{}

var GL033 = &gl033{}

func (r *gl033) ID() string { return "GL033" }

func (r *gl033) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkDebugVars(parser.FindKey(mapping, "variables"), file, "")...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkDebugVars(parser.FindKey(def, "variables"), file, "")...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		findings = append(findings, checkDebugVars(parser.FindKey(job, "variables"), file, name.Value)...)
	})

	return findings
}

// checkDebugVars flags GitLab debug toggles committed in a variables: block.
// CI_DEBUG_TRACE dumps every variable value to the log (error); CI_DEBUG_SERVICES
// dumps service-container logs including their credentials (warn).
func checkDebugVars(node *yaml.Node, file, job string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		scalar := resolveScalar(node.Content[i+1])
		if scalar == nil {
			continue
		}
		switch key.Value {
		case "CI_DEBUG_TRACE":
			if scalar.Value != "true" {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL033",
				Severity: finding.Error,
				Job:      job,
				Message:  "CI_DEBUG_TRACE: \"true\" is committed — shell tracing dumps all variable values including secrets to the job log; remove it and use the GitLab UI run-pipeline dialog for transient debugging",
				File:     file,
				Line:     key.Line,
				Col:      key.Column,
			})
		case "CI_DEBUG_SERVICES":
			if !isDebugTruthy(scalar.Value) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL033",
				Severity: finding.Warn,
				Job:      job,
				Message:  "CI_DEBUG_SERVICES: \"true\" is committed — verbose service-container logging leaks their startup environment and credentials to the job log; remove it and use the GitLab UI run-pipeline dialog for transient debugging",
				File:     file,
				Line:     key.Line,
				Col:      key.Column,
			})
		}
	}
	return findings
}

// isDebugTruthy reports whether v enables a GitLab debug toggle. GitLab treats
// "true" and "1" as on for CI_DEBUG_SERVICES.
func isDebugTruthy(v string) bool {
	return v == "true" || v == "1"
}
