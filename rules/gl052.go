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

type gl052 struct{}

var GL052 = &gl052{}

func (r *gl052) ID() string { return "GL052" }

// envNameUserVars extends the GL002 set with CI_COMMIT_REF_SLUG, which is a
// normalised form of CI_COMMIT_REF_NAME and carries the same spoofing risk.
var envNameUserVars = append(
	[]string{"CI_COMMIT_REF_SLUG"},
	userControlledVars...,
)

var envNameUserVarRe = mustCompilePrefiltered(
	`\$\{?(` + strings.Join(envNameUserVars, "|") + `)\b`,
)

func (r *gl052) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	aliases := newUserAliases(doc)
	parser.EachJob(doc, func(nameNode *yaml.Node, jobNode *yaml.Node) {
		env := parser.FindKey(jobNode, "environment")
		if env == nil {
			return
		}
		var nameNode2 *yaml.Node
		switch env.Kind {
		case yaml.ScalarNode:
			nameNode2 = env
		case yaml.MappingNode:
			nameNode2 = parser.FindKey(env, "name")
		}
		if nameNode2 == nil || nameNode2.Kind != yaml.ScalarNode {
			return
		}
		// A variable that references a user-controlled one is user-controlled
		// too (#1504).
		envName, used := aliases.expand(nameNode2.Value, nameNode.Value)
		matches := envNameUserVarRe.FindAllStringSubmatch(envName, -1)
		seen := map[string]bool{}
		for _, m := range matches {
			varName := m[1]
			if seen[varName] {
				continue
			}
			seen[varName] = true
			note := ""
			if used != nil && !mentionsVar(nameNode2.Value, varName) {
				note = aliasNote(used)
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL052",
				Severity: finding.Warn,
				Job:      nameNode.Value,
				Message: fmt.Sprintf(
					"user-controlled variable $%s in environment:name: — attacker can craft a branch name that resolves to a protected environment and access its secrets%s",
					varName, note,
				),
				File: file,
				Line: nameNode2.Line,
				Col:  nameNode2.Column,
			})
		}
	})
	return findings
}
