// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl053 struct{}

var GL053 = &gl053{}

func (r *gl053) ID() string { return "GL053" }

// workflowSourceVarRe matches the CI variables that, when referenced in a
// workflow:rules:if, indicate the pipeline is gated on a trusted source or
// branch rather than running for every event.
var workflowSourceVarRe = regexp.MustCompile(
	`\$\{?(CI_PIPELINE_SOURCE|CI_COMMIT_BRANCH|CI_COMMIT_REF_NAME|CI_COMMIT_REF_SLUG|CI_COMMIT_TAG|CI_MERGE_REQUEST_(?:IID|ID|EVENT_TYPE|SOURCE_BRANCH_NAME|TARGET_BRANCH_NAME)|CI_DEFAULT_BRANCH)\b`,
)

func (r *gl053) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	if mapping.Kind != yaml.MappingNode {
		return nil
	}

	keyNode, workflowNode := parser.FindKeyNode(mapping, "workflow")
	if workflowNode == nil && includesWorkflowTemplate(parser.FindKey(mapping, "include")) {
		return nil
	}
	// workflow: !reference [...] pulls the rules from a job glsec may not see.
	if workflowNode != nil && workflowNode.Tag == "!reference" {
		return nil
	}
	if workflowNode == nil {
		return []finding.Finding{{
			RuleID:   "GL053",
			Severity: finding.Warn,
			Message:  "no top-level workflow:rules — pipelines run for every push, tag, trigger, API call and merge request event, also a fork's merge request that a member runs in this project; gate on $CI_PIPELINE_SOURCE or branch to block untrusted pipeline execution",
			File:     file,
			Line:     1,
			Col:      1,
		}}
	}

	rulesNode := parser.FindKey(workflowNode, "rules")
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode || len(rulesNode.Content) == 0 {
		return []finding.Finding{{
			RuleID:   "GL053",
			Severity: finding.Warn,
			Message:  "workflow: block has no rules: restricting pipeline source — pipelines run for every event; gate on $CI_PIPELINE_SOURCE or branch",
			File:     file,
			Line:     keyNode.Line,
			Col:      keyNode.Column,
		}}
	}

	if rulesNode.Tag == "!reference" || workflowRulesRestrictSource(rulesNode) || onlyNever(rulesNode) {
		return nil
	}

	return []finding.Finding{{
		RuleID:   "GL053",
		Severity: finding.Warn,
		Message:  "workflow:rules does not gate on pipeline source or branch — add an if: on $CI_PIPELINE_SOURCE, $CI_COMMIT_BRANCH, or $CI_MERGE_REQUEST_IID to block untrusted pipeline execution",
		File:     file,
		Line:     keyNode.Line,
		Col:      keyNode.Column,
	}}
}

// workflowRulesRestrictSource reports whether any rule item gates on a
// trusted pipeline source or branch via its if: condition.
// includesWorkflowTemplate reports whether include: pulls in one of GitLab's
// Workflows/ templates (Branch-Pipelines, MergeRequest-Pipelines), which
// define workflow:rules gated on the pipeline source.
func includesWorkflowTemplate(include *yaml.Node) bool {
	if include == nil {
		return false
	}
	items := []*yaml.Node{include}
	if include.Kind == yaml.SequenceNode {
		items = include.Content
	}
	for _, it := range items {
		if it.Kind != yaml.MappingNode {
			continue
		}
		if t := parser.FindKey(it, "template"); t != nil && t.Kind == yaml.ScalarNode && strings.HasPrefix(t.Value, "Workflows/") {
			return true
		}
	}
	return false
}

// onlyNever reports whether every workflow rule is when: never, so no
// pipeline runs at all.
func onlyNever(rulesNode *yaml.Node) bool {
	for _, item := range rulesNode.Content {
		w := parser.FindKey(item, "when")
		if item.Kind != yaml.MappingNode || w == nil || w.Value != "never" {
			return false
		}
	}
	return len(rulesNode.Content) > 0
}

func workflowRulesRestrictSource(rulesNode *yaml.Node) bool {
	for _, item := range rulesNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode != nil && ifNode.Kind == yaml.ScalarNode && workflowSourceVarRe.MatchString(ifNode.Value) {
			return true
		}
	}
	return false
}
