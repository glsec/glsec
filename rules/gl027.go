// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl027 struct{}

var GL027 = &gl027{}

func (r *gl027) ID() string { return "GL027" }

func (r *gl027) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		findings = append(findings, checkCommittedSecretVariables(vars, file, job)...)
	})

	return findings
}

func checkCommittedSecretVariables(node *yaml.Node, file, job string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		varName := node.Content[i].Value
		val := node.Content[i+1]

		// The long form (value: + description:) is what pre-fills the Run
		// pipeline form. Short-form secret-like names are mostly throwaway
		// passwords for service containers and are left to GL006's formats.
		if val.Kind != yaml.MappingNode || !hasSecretSuffix(varName) {
			continue
		}
		v := parser.FindKey(val, "value")
		if v == nil || v.Kind != yaml.ScalarNode || !committedSecretValue(v.Value) {
			continue
		}
		// A value that repeats the variable's name is a placeholder (#991).
		if strings.EqualFold(strings.Trim(v.Value, "_-<> "), varName) {
			continue
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL027",
			Severity: finding.Warn,
			Job:      job,
			Message: fmt.Sprintf(
				"variable %q has a secret-like name and a value committed in the pipeline file — everyone who can read the repository or open the Run pipeline form sees it, and .gitlab-ci.yml has no masked: setting; store it as a masked CI/CD variable in Settings → CI/CD → Variables and keep only the description here",
				varName,
			),
			File: file,
			Line: node.Content[i].Line,
			Col:  node.Content[i].Column,
		})
	}
	return findings
}

// committedSecretValue reports whether v is a literal value worth reporting:
// not empty, not a reference to another variable (GL018), not a placeholder,
// and not a known token format, which GL006 already reports as an error.
func committedSecretValue(v string) bool {
	if v == "" || strings.HasPrefix(v, "$") || looksLikePlaceholder(v) {
		return false
	}
	for _, pat := range secretPatterns {
		if pat.re.MatchString(v) {
			return false
		}
	}
	return true
}
