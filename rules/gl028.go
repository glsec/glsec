// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl028 struct{}

var GL028 = &gl028{}

func (r *gl028) ID() string { return "GL028" }

func (r *gl028) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		artifactsNode := parser.FindKey(job, "artifacts")
		if artifactsNode == nil || artifactsNode.Kind != yaml.MappingNode {
			return
		}

		untrackedNode := parser.FindKey(artifactsNode, "untracked")
		if !parser.IsTrue(untrackedNode) {
			return
		}

		// Safe only if exclude: contains a pattern that matches sensitive files.
		if hasSensitiveArtifactExclude(parser.FindKey(artifactsNode, "exclude")) {
			return
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL028",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "artifacts:untracked:true — exclude: is missing or does not cover sensitive files; remove untracked:true and list required files under paths:, or exclude .env, keys, and credentials",
			File:     file,
			Line:     untrackedNode.Line,
			Col:      untrackedNode.Column,
		})
	})

	return findings
}

func hasSensitiveArtifactExclude(excludeNode *yaml.Node) bool {
	if excludeNode == nil || excludeNode.Kind != yaml.SequenceNode {
		return false
	}

	for _, item := range excludeNode.Content {
		// exclude: is not recursive; a directory entry does not filter its files.
		if item.Kind != yaml.ScalarNode || strings.HasSuffix(item.Value, "/") {
			continue
		}
		if matchesSensitivePattern(item.Value) != "" {
			return true
		}
	}

	return false
}
