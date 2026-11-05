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

type gl073 struct{}

var GL073 = &gl073{}

func (r *gl073) ID() string { return "GL073" }

func (r *gl073) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)
	in := NewInheritance(doc)

	if def := parser.FindKey(mapping, "default"); def != nil {
		if artifactsNode := parser.FindKey(def, "artifacts"); artifactsNode != nil {
			findings = append(findings, checkArtifactExposure(doc, nil, artifactsNode, file)...)
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		artifactsNode := parser.FindKey(job, "artifacts")
		if artifactsNode == nil {
			return
		}
		for _, f := range checkArtifactExposure(doc, in, artifactsNode, file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

// in is nil for the artifacts block under default:.
func checkArtifactExposure(doc *yaml.Node, in *Inheritance, node *yaml.Node, file string) []finding.Finding {
	keyNode, exposeDesc := artifactExposure(node)
	if keyNode == nil {
		return nil
	}

	severity := finding.Warn
	msg := fmt.Sprintf(
		"artifacts readable by everyone who can see the pipeline (%s) — in a public project that includes anonymous users, without a GitLab account; restrict with artifacts:access: developer (or none)",
		exposeDesc,
	)
	if sensitive := sensitiveArtifactPath(doc, in, node); sensitive != "" {
		severity = finding.Error
		msg = fmt.Sprintf(
			"artifacts readable by everyone who can see the pipeline (%s) include a sensitive path %q — in a public project anyone can download the secrets without a GitLab account; restrict with artifacts:access: developer (or none)",
			exposeDesc, sensitive,
		)
	}

	return []finding.Finding{{
		RuleID:   "GL073",
		Severity: severity,
		Message:  msg,
		File:     file,
		Line:     keyNode.Line,
		Col:      keyNode.Column,
	}}
}

// artifactExposure reports the key node and a description when the artifacts
// block explicitly grants anonymous access via public: true or access: all.
// The absent/default case is deliberately not flagged to avoid firing on every
// artifacts block.
func artifactExposure(node *yaml.Node) (*yaml.Node, string) {
	if k, v := parser.FindKeyNode(node, "public"); v != nil && v.Kind == yaml.ScalarNode {
		if strings.EqualFold(v.Value, "true") {
			return k, "public: true"
		}
	}
	if k, v := parser.FindKeyNode(node, "access"); v != nil && v.Kind == yaml.ScalarNode {
		if strings.EqualFold(v.Value, "all") {
			return k, "access: all"
		}
	}
	return nil, ""
}

// sensitiveArtifactPath returns the first path under paths: that matches a
// sensitive pattern, skipping a placeholder-only npm or Yarn config the
// jobs write themselves (#1171).
func sensitiveArtifactPath(doc *yaml.Node, in *Inheritance, node *yaml.Node) string {
	seqNode := parser.FindKey(node, "paths")
	if seqNode == nil || seqNode.Kind != yaml.SequenceNode {
		return ""
	}
	for _, item := range seqNode.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if matchesSensitivePattern(item.Value) != "" && !writesPlaceholderOnly(doc, in, node, item.Value) {
			return item.Value
		}
	}
	return ""
}
