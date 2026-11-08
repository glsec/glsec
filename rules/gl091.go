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

type gl091 struct{}

var GL091 = &gl091{}

func (r *gl091) ID() string { return "GL091" }

// spoofableIdentityVars name an actor by data the actor controls (#1134):
// CI_COMMIT_AUTHOR is the commit's git author, set with git commit --author;
// GITLAB_USER_NAME is the profile's display name, editable and not unique;
// CI_COMMIT_USER_LOGIN is the user whose public email the commit's author
// email names, so writing someone's public email into a commit gives their
// username.
var spoofableIdentityVars = map[string]string{
	"CI_COMMIT_AUTHOR":     "the commit's git author, which whoever creates the commit sets freely (git commit --author)",
	"GITLAB_USER_NAME":     "the user's display name, which every user can change and which isn't unique",
	"CI_COMMIT_USER_LOGIN": "looked up from the commit's author email, which whoever creates the commit sets freely; a user's public email in a commit gives their username",
}

const spoofableIdentityAlt = `CI_COMMIT_AUTHOR|GITLAB_USER_NAME|CI_COMMIT_USER_LOGIN`

var (
	// identityGateRe matches a positive comparison of a spoofable identity
	// variable: $VAR == "x", $VAR =~ /x/. Group 1 is the variable, group 2
	// the compared value.
	identityGateRe = regexp.MustCompile(`\$\{?(` + spoofableIdentityAlt + `)\}?\s*(?:==|=~)\s*("[^"]*"|'[^']*'|/(?:\\.|[^/])*/|\$\{?\w+\}?|\w+)`)
	// identityGateRevRe matches the operands the other way round: "x" == $VAR.
	identityGateRevRe = regexp.MustCompile(`("[^"]*"|'[^']*')\s*==\s*\$\{?(` + spoofableIdentityAlt + `)\}?\b`)
)

// Check reports a rules:if that decides whether a job, pipeline or include
// runs by a positive match on an identity the actor controls. A negative
// match (!=, !~) or a when: never rule only keeps something from running,
// so it grants nothing.
func (r *gl091) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)
	if wf := parser.FindKey(mapping, "workflow"); wf != nil {
		findings = append(findings, identityGates(parser.FindKey(wf, "rules"), file, "")...)
	}
	if inc := parser.FindKey(mapping, "include"); inc != nil {
		entries := []*yaml.Node{inc}
		if inc.Kind == yaml.SequenceNode {
			entries = inc.Content
		}
		for _, e := range entries {
			if e.Kind == yaml.MappingNode {
				findings = append(findings, identityGates(parser.FindKey(e, "rules"), file, "")...)
			}
		}
	}
	parser.EachJob(doc, func(name, job *yaml.Node) {
		findings = append(findings, identityGates(parser.FindKey(job, "rules"), file, name.Value)...)
	})
	return findings
}

func identityGates(rules *yaml.Node, file, job string) []finding.Finding {
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range rules.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
			continue
		}
		if when := parser.FindKey(item, "when"); when != nil && when.Value == "never" {
			continue
		}
		v := spoofedVar(ifNode.Value)
		if v == "" {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL091",
			Severity: finding.Warn,
			Job:      job,
			Message:  fmt.Sprintf("rules:if trusts $%s, %s — match the account instead: $GITLAB_USER_LOGIN == \"<username>\" or $GITLAB_USER_ID", v, spoofableIdentityVars[v]),
			File:     file,
			Line:     ifNode.Line,
			Col:      ifNode.Column,
		})
	}
	return findings
}

// spoofedVar returns the first spoofable identity variable the expression
// matches positively against a value, or "". A comparison with null or an
// empty string only tests whether the variable is set. Each || alternative is
// read on its own.
func spoofedVar(expr string) string {
	if !strings.Contains(expr, "CI_COMMIT_AUTHOR") && !strings.Contains(expr, "GITLAB_USER_NAME") && !strings.Contains(expr, "CI_COMMIT_USER_LOGIN") {
		return ""
	}
	for _, alt := range topLevelSplit(expr, "||") {
		// In a push pipeline GITLAB_USER_NAME is the pusher, who wrote the
		// YAML that runs: the gate filters, it grants nothing (#1287).
		pushOnly := pushSourceRe.MatchString(depthZero(alt))
		skipped := func(v string) bool { return pushOnly && v == "GITLAB_USER_NAME" }
		for _, m := range identityGateRe.FindAllStringSubmatch(alt, -1) {
			if !emptyOperand(m[2]) && !skipped(m[1]) {
				return m[1]
			}
		}
		for _, m := range identityGateRevRe.FindAllStringSubmatch(alt, -1) {
			if !emptyOperand(m[1]) && !skipped(m[2]) {
				return m[2]
			}
		}
	}
	return ""
}

// pushSourceRe matches a comparison pinning the pipeline source to a push.
var pushSourceRe = regexp.MustCompile(`\$\{?CI_PIPELINE_SOURCE\}?\s*==\s*["']push["']|["']push["']\s*==\s*\$\{?CI_PIPELINE_SOURCE\b`)

// topLevelSplit splits expr at sep outside parentheses and quotes.
func topLevelSplit(expr, sep string) []string {
	var parts []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && strings.HasPrefix(expr[i:], sep):
			parts = append(parts, expr[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	return append(parts, expr[start:])
}

// depthZero blanks what expr has inside parentheses, so a match in it is part
// of the && conjunction itself.
func depthZero(expr string) string {
	b := []byte(expr)
	depth := 0
	for i, c := range b {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth > 0 {
				b[i] = ' '
			}
		}
	}
	return string(b)
}

func emptyOperand(s string) bool {
	return s == "null" || s == `""` || s == "''"
}
