package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl055 struct{}

var GL055 = &gl055{}

func (r *gl055) ID() string { return "GL055" }

const dockerSocketPath = "/var/run/docker.sock"

func (r *gl055) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkDockerSocket(
		parser.FindKey(mapping, "services"), parser.FindKey(mapping, "variables"), file, "")...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkDockerSocket(
			parser.FindKey(def, "services"), parser.FindKey(def, "variables"), file, "")...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		findings = append(findings, checkDockerSocket(
			parser.FindKey(job, "services"), parser.FindKey(job, "variables"), file, name.Value)...)
	})

	return findings
}

// checkDockerSocket flags a host Docker socket exposed to a job — either as a
// service volume mount or via a DOCKER_HOST unix-socket variable. A volume
// mount is the more explicit signal; when present, the DOCKER_HOST check for
// the same scope is skipped to avoid a redundant second finding.
func checkDockerSocket(servicesNode, varsNode *yaml.Node, file, job string) []finding.Finding {
	var findings []finding.Finding

	if servicesNode != nil && servicesNode.Kind == yaml.SequenceNode {
		for _, item := range servicesNode.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			volumes := parser.FindKey(item, "volumes")
			if volumes == nil || volumes.Kind != yaml.SequenceNode {
				continue
			}
			for _, v := range volumes.Content {
				if v.Kind == yaml.ScalarNode && strings.Contains(v.Value, dockerSocketPath) {
					findings = append(findings, finding.Finding{
						RuleID:   "GL055",
						Severity: finding.Warn,
						Job:      job,
						Message:  "host Docker socket " + dockerSocketPath + " mounted into a service — grants full control of the runner's Docker daemon (container escape, access to other jobs' secrets); use TLS-based docker:dind (tcp://docker:2376) instead",
						File:     file, Line: v.Line, Col: v.Column,
					})
				}
			}
		}
	}

	if len(findings) > 0 {
		return findings
	}

	if varsNode != nil && varsNode.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(varsNode.Content); i += 2 {
			key := varsNode.Content[i]
			val := resolveScalar(varsNode.Content[i+1])
			if key.Value == "DOCKER_HOST" && val != nil && strings.Contains(val.Value, dockerSocketPath) {
				return []finding.Finding{{
					RuleID:   "GL055",
					Severity: finding.Warn,
					Job:      job,
					Message:  "DOCKER_HOST points at the host Docker socket (" + dockerSocketPath + ") — the job can control the runner's Docker daemon; use TLS-based docker:dind (tcp://docker:2376) instead",
					File:     file, Line: key.Line, Col: key.Column,
				}}
			}
		}
	}

	return nil
}
