package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl054 struct{}

var GL054 = &gl054{}

func (r *gl054) ID() string { return "GL054" }

// dindImageRe matches a docker-in-docker service image: docker:dind,
// docker:26.0-dind, registry/docker:24-dind, etc.
var dindImageRe = regexp.MustCompile(`(?:^|/)docker:[\w.-]*dind\b`)

// dockerHostTCPRe matches a DOCKER_HOST value pointing at the dind daemon.
var dockerHostTCPRe = regexp.MustCompile(`tcp://docker:23(?:75|76)\b`)

func (r *gl054) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkDinD(
		parser.FindKey(mapping, "services"), parser.FindKey(mapping, "variables"), file, "")...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkDinD(
			parser.FindKey(def, "services"), parser.FindKey(def, "variables"), file, "")...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		findings = append(findings, checkDinD(
			parser.FindKey(job, "services"), parser.FindKey(job, "variables"), file, name.Value)...)
	})

	return findings
}

// checkDinD flags a docker-in-docker service or, failing that, a DOCKER_HOST
// variable pointing at the dind daemon. The service is the stronger signal, so
// when both are present in the same scope only the service is reported.
func checkDinD(servicesNode, varsNode *yaml.Node, file, job string) []finding.Finding {
	if servicesNode != nil && servicesNode.Kind == yaml.SequenceNode {
		for _, item := range servicesNode.Content {
			ref, line, col := imageRef(item)
			if ref != "" && dindImageRe.MatchString(ref) {
				return []finding.Finding{{
					RuleID:   "GL054",
					Severity: finding.Warn,
					Job:      job,
					Message: fmt.Sprintf(
						"docker-in-docker service %q requires the runner to run privileged (full host root access) — consider rootless build tools like Kaniko or Buildah, or document the privileged-runner requirement",
						ref,
					),
					File: file, Line: line, Col: col,
				}}
			}
		}
	}

	if varsNode != nil && varsNode.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(varsNode.Content); i += 2 {
			key := varsNode.Content[i]
			val := resolveScalar(varsNode.Content[i+1])
			if key.Value == "DOCKER_HOST" && val != nil && dockerHostTCPRe.MatchString(val.Value) {
				return []finding.Finding{{
					RuleID:   "GL054",
					Severity: finding.Warn,
					Job:      job,
					Message:  "DOCKER_HOST points at a docker-in-docker daemon (tcp://docker:2375/2376) — implies a privileged runner; consider rootless build tools like Kaniko or Buildah",
					File:     file, Line: key.Line, Col: key.Column,
				}}
			}
		}
	}

	return nil
}
