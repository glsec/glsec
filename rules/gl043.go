package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl043 struct{}

var GL043 = &gl043{}

func (r *gl043) ID() string { return "GL043" }

// gl043Vars are predefined variables commonly used in access-control conditions
// whose values are set by external actors (pusher, MR creator, API caller).
var gl043Vars = []string{
	"GITLAB_USER_LOGIN",
	"CI_COMMIT_BRANCH",
	"CI_COMMIT_REF_NAME",
	"CI_PROJECT_NAMESPACE",
}

// gl043Re matches "$VAR =~ /pattern/" in a rules:if condition string.
// Group 1: variable name, Group 2: regex pattern content (between slashes).
var gl043Re = regexp.MustCompile(
	`\$\{?(` + strings.Join(gl043Vars, "|") + `)\}?\s*=~\s*/([^/]*)/`,
)

func (r *gl043) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	if wf := parser.FindKey(mapping, "workflow"); wf != nil {
		if rulesNode := parser.FindKey(wf, "rules"); rulesNode != nil {
			findings = append(findings, checkRulesIfNodes(rulesNode, file, "")...)
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		rulesNode := parser.FindKey(job, "rules")
		if rulesNode == nil {
			return
		}
		for _, f := range checkRulesIfNodes(rulesNode, file, "") {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func checkRulesIfNodes(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
			continue
		}
		findings = append(findings, checkIfCondition(ifNode, file)...)
	}
	return findings
}

func checkIfCondition(node *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	matches := gl043Re.FindAllStringSubmatch(node.Value, -1)
	for _, m := range matches {
		varName := m[1]
		pattern := m[2]

		hasStart := strings.HasPrefix(pattern, "^")
		hasEnd := strings.HasSuffix(pattern, "$")

		if hasEnd {
			continue
		}

		var msg string
		if hasStart {
			msg = fmt.Sprintf(
				"rules:if uses $%s =~ /%s/ — no trailing $ anchor; a value prefixed with %q also matches",
				varName, pattern, strings.TrimPrefix(pattern, "^"),
			)
		} else {
			msg = fmt.Sprintf(
				"rules:if uses $%s =~ /%s/ — no ^ or $ anchors; any value containing %q matches",
				varName, pattern, pattern,
			)
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL043",
			Severity: finding.Warn,
			Message:  msg,
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		})
	}
	return findings
}
