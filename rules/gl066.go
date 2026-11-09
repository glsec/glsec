// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
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
var dockerAuthKeyRe = mustCompilePrefiltered(`"auths?"\s*:`)

func (r *gl066) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		for _, f := range checkDockerAuthConfig(vars, file) {
			f.Job = job
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
		// Every credential a variable reference is the runtime-expanded form:
		// GitLab fills it from masked CI/CD variables, so the file holds none.
		if dockerAuthCredentialsAreVariables(v) {
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

// dockerAuthCredentialFields lists the JSON members of a registry entry that
// carry credentials; the registry key itself is a variable in the usual
// runtime-expanded form and is not inspected.
var dockerAuthCredentialFields = []string{"username", "password", "auth", "identitytoken", "registrytoken"}

// dockerAuthCredentialsAreVariables reports whether every credential value in
// an inline DOCKER_AUTH_CONFIG document is a variable reference ($VAR or
// ${VAR}). Only a document that parses as JSON and actually carries a
// credential field can pass; anything else stays reported.
func dockerAuthCredentialsAreVariables(v string) bool {
	var doc map[string]any
	if err := json.Unmarshal([]byte(v), &doc); err != nil {
		return false
	}
	if auths, ok := doc["auths"].(map[string]any); ok {
		return registryCredentialsAreVariables(auths)
	}
	auth, ok := doc["auth"]
	return ok && isVariableReferenceValue(auth)
}

func registryCredentialsAreVariables(auths map[string]any) bool {
	sawCredential := false
	for _, entry := range auths {
		registry, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		for _, field := range dockerAuthCredentialFields {
			value, ok := registry[field]
			if !ok {
				continue
			}
			sawCredential = true
			if !isVariableReferenceValue(value) {
				return false
			}
		}
	}
	return sawCredential
}

func isVariableReferenceValue(value any) bool {
	s, ok := value.(string)
	return ok && varRefRe.MatchString(strings.TrimSpace(s))
}
