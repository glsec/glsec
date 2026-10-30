// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

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
// A slash right after a backslash is part of the pattern, not its end (#700),
// also after an escaped backslash, as GitLab's lexer reads it
// (lib/gitlab/ci/pipeline/expression/lexeme/pattern.rb, #987).
var gl043Re = regexp.MustCompile(
	`\$\{?(` + strings.Join(gl043Vars, "|") + `)\}?\s*=~\s*/((?:\\/|[^/])*)/`,
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
		// A broader match of a when: never rule only excludes more
		// pipelines (#987).
		if when := parser.FindKey(item, "when"); when != nil && when.Value == "never" {
			continue
		}
		findings = append(findings, checkIfCondition(ifNode, file)...)
	}
	return findings
}

// isLiteralNamespacePrefix reports whether pattern is a literal namespace
// prefix ending in an escaped slash, such as ^mygroup\/ or ^mygroup\/sub\/:
// an optional ^ or \A start anchor, then only literal namespace path
// characters (letters, digits, _ and -, plus escaped . - _ and /), ending
// in \/. Anything else, such as an unescaped . or a character class, could
// match a group that is not a subgroup of the named one.
func isLiteralNamespacePrefix(pattern string) bool {
	p := strings.TrimPrefix(strings.TrimPrefix(pattern, "^"), `\A`)
	if !strings.HasSuffix(p, `\/`) {
		return false
	}
	p = strings.TrimSuffix(p, `\/`)
	if p == "" {
		return false
	}
	for i := 0; i < len(p); {
		c := p[i]
		if c == '\\' {
			if i+1 >= len(p) {
				return false
			}
			switch p[i+1] {
			case '.', '-', '_', '/':
			default:
				return false
			}
			i += 2
			continue
		}
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			i++
			continue
		}
		return false
	}
	return true
}

func checkIfCondition(node *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	matches := gl043Re.FindAllStringSubmatch(node.Value, -1)
	for _, m := range matches {
		varName := m[1]
		pattern := m[2]

		// \A and \z are anchors too, and a trailing .* already runs to the end
		// of the value, so it needs no $.
		hasStart := strings.HasPrefix(pattern, "^") || strings.HasPrefix(pattern, `\A`)
		hasEnd := strings.HasSuffix(pattern, "$") || strings.HasSuffix(pattern, `\z`) || runsToEnd(pattern)

		if hasEnd {
			continue
		}

		// A namespace prefix ending in / only matches the group's
		// subgroups (#820): a project directly in the group has no
		// trailing slash in $CI_PROJECT_NAMESPACE, so it does not
		// match. Only that group's owners can create a subgroup, so
		// the prefix match is intended, not a bypass. This
		// applies to $CI_PROJECT_NAMESPACE only; $CI_PROJECT_ROOT_NAMESPACE
		// and $CI_PROJECT_PATH are not matched by this rule at all, so they
		// already produce no finding here. The prefix itself must be
		// literal: a metacharacter such as . could match a different group.
		if varName == "CI_PROJECT_NAMESPACE" && hasStart && isLiteralNamespacePrefix(pattern) {
			continue
		}

		var msg string
		prefix := strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(pattern, "^"), `\A`), `\/`, "/")
		switch {
		case hasStart && strings.ContainsAny(prefix, `|()[]{}*+?.\`):
			// Regex syntax isn't a literal prefix to quote (#987).
			msg = fmt.Sprintf(
				"rules:if uses $%s =~ /%s/ — no trailing $ anchor; any longer value that starts with a match also matches",
				varName, pattern,
			)
		case hasStart:
			msg = fmt.Sprintf(
				"rules:if uses $%s =~ /%s/ — no trailing $ anchor; a value starting with \"%s\" also matches",
				varName, pattern, prefix,
			)
		default:
			msg = fmt.Sprintf(
				"rules:if uses $%s =~ /%s/ — no ^ or $ anchors; any value containing \"%s\" matches",
				varName, pattern, strings.ReplaceAll(pattern, `\/`, "/"),
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

// runsToEnd reports whether a pattern ends in .* or .+, also as a group
// ((.*), (.+)): it already matches up to the end of the value (#987).
func runsToEnd(pattern string) bool {
	for _, tail := range []string{".*", ".+", "(.*)", "(.+)"} {
		if strings.HasSuffix(pattern, tail) && !strings.HasSuffix(pattern, `\`+tail) {
			return true
		}
	}
	return false
}
