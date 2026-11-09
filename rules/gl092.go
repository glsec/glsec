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

type gl092 struct{}

// GL092 reports a job that publishes a package with a trusted publisher's
// OIDC token and has no environment: (#1298).
var GL092 = &gl092{}

func (r *gl092) ID() string { return "GL092" }

// trustedPublisher is a package registry that accepts a GitLab OIDC token
// for publishing and can bind the trusted publisher to an environment.
type trustedPublisher struct {
	name      string
	audiences []string
	publishes func(words []string) bool
}

// trustedPublishers are the registries whose GitLab audience and environment
// binding are documented: PyPI (and TestPyPI) and npm.
var trustedPublishers = []trustedPublisher{
	{"PyPI", []string{"pypi", "testpypi"}, pythonPublishes},
	{"npm", []string{"npm:registry.npmjs.org"}, npmPublishes},
}

func (r *gl092) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)
	parser.EachJob(doc, func(name, job *yaml.Node) {
		if !runsInheritedJob(in, name, job) {
			return
		}
		tokens := in.Key(job, "id_tokens")
		if tokens == nil || tokens.Kind != yaml.MappingNode || hasEnvironment(in.Key(job, "environment")) {
			return
		}
		var words [][]string
		for _, line := range CollectJobScriptLines(in.Effective(job)) {
			for _, cmd := range shellCommands(line.Value) {
				words = append(words, commandWords(cmd.text))
			}
		}
		for i := 0; i+1 < len(tokens.Content); i += 2 {
			tokenName, token := tokens.Content[i], tokens.Content[i+1]
			for _, tp := range trustedPublishers {
				if !hasAudience(token, tp.audiences) || !anyCommand(words, tp.publishes) {
					continue
				}
				findings = append(findings, finding.Finding{
					RuleID:   "GL092",
					Severity: finding.Info,
					Job:      name.Value,
					Message:  fmt.Sprintf("job %q publishes to %s with the OIDC token %q but has no environment: — the trusted publisher can't be bound to an environment, so a pipeline that runs this job can publish; add environment: (for example release), protect it, and name it in the publisher's settings", name.Value, tp.name, tokenName.Value),
					File:     file,
					Line:     tokenName.Line,
					Col:      tokenName.Column,
				})
			}
		}
	})
	return findings
}

// hasEnvironment reports an environment: with a name, written as a string or
// as a mapping with name:.
func hasEnvironment(env *yaml.Node) bool {
	switch {
	case env == nil:
		return false
	case env.Kind == yaml.ScalarNode:
		return strings.TrimSpace(env.Value) != ""
	case env.Kind == yaml.MappingNode:
		n := parser.FindKey(env, "name")
		return n != nil && n.Kind == yaml.ScalarNode && strings.TrimSpace(n.Value) != ""
	}
	return false
}

// hasAudience reports whether an id_tokens entry asks for one of audiences:
// aud: as a string or a list.
func hasAudience(token *yaml.Node, audiences []string) bool {
	aud := parser.FindKey(token, "aud")
	if aud == nil {
		return false
	}
	values := []*yaml.Node{aud}
	if aud.Kind == yaml.SequenceNode {
		values = aud.Content
	}
	for _, v := range values {
		for _, want := range audiences {
			if v.Kind == yaml.ScalarNode && v.Value == want {
				return true
			}
		}
	}
	return false
}

func anyCommand(words [][]string, match func([]string) bool) bool {
	for _, w := range words {
		if match(w) {
			return true
		}
	}
	return false
}
