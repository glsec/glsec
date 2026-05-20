package rules

import (
	"fmt"
	"regexp"
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

var envNameUserVarRe = regexp.MustCompile(
	`\$\{?(` + strings.Join(envNameUserVars, "|") + `)\b`,
)

func (r *gl052) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
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
		matches := envNameUserVarRe.FindAllStringSubmatch(nameNode2.Value, -1)
		seen := map[string]bool{}
		for _, m := range matches {
			varName := m[1]
			if seen[varName] {
				continue
			}
			seen[varName] = true
			findings = append(findings, finding.Finding{
				RuleID:   "GL052",
				Severity: finding.Warn,
				Job:      nameNode.Value,
				Message: fmt.Sprintf(
					"user-controlled variable $%s in environment:name: — attacker can craft a branch name that resolves to a protected environment and access its secrets",
					varName,
				),
				File: file,
				Line: nameNode2.Line,
				Col:  nameNode2.Column,
			})
		}
	})
	return findings
}
