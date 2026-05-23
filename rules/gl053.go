package rules

import (
	"regexp"

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
	`\$\{?(CI_PIPELINE_SOURCE|CI_COMMIT_BRANCH|CI_COMMIT_REF_NAME|CI_COMMIT_REF_SLUG|CI_COMMIT_TAG|CI_MERGE_REQUEST_IID|CI_DEFAULT_BRANCH)\b`,
)

func (r *gl053) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	if mapping.Kind != yaml.MappingNode {
		return nil
	}

	keyNode, workflowNode := parser.FindKeyNode(mapping, "workflow")
	if workflowNode == nil {
		return []finding.Finding{{
			RuleID:   "GL053",
			Severity: finding.Warn,
			Message:  "no top-level workflow:rules — pipelines run for every event, including merge requests from forks; gate on $CI_PIPELINE_SOURCE or branch to block untrusted pipeline execution",
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

	if workflowRulesRestrictSource(rulesNode) {
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
