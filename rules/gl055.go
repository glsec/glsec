// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl055 struct{}

var GL055 = &gl055{}

func (r *gl055) ID() string { return "GL055" }

const dockerSocketPath = "/var/run/docker.sock"

func (r *gl055) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		if f := checkDockerSocketVars(vars, file, job); f != nil {
			findings = append(findings, *f)
		}
	})

	return findings
}

// checkDockerSocketVars flags a DOCKER_HOST variable pointing at the host
// Docker socket. The socket itself is mounted via runner config.toml, not
// .gitlab-ci.yml, so the DOCKER_HOST reference is the statically detectable
// signal that a job is wired to control the host daemon.
func checkDockerSocketVars(node *yaml.Node, file, job string) *finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := resolveScalar(node.Content[i+1])
		if key.Value != "DOCKER_HOST" || val == nil || !strings.Contains(val.Value, dockerSocketPath) {
			continue
		}
		return &finding.Finding{
			RuleID:   "GL055",
			Severity: finding.Warn,
			Job:      job,
			Message:  "DOCKER_HOST points at the host Docker socket (" + dockerSocketPath + ") — the job can control the runner's Docker daemon (container escape, access to other jobs' secrets); use TLS-based docker:dind (tcp://docker:2376) instead",
			File:     file, Line: key.Line, Col: key.Column,
		}
	}
	return nil
}
