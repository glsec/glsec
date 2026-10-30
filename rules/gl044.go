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

type gl044 struct{}

var GL044 = &gl044{}

func (r *gl044) ID() string { return "GL044" }

// mrSourceSHARe matches any reference to CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
// in POSIX shell form ($CI_MERGE_REQUEST_SOURCE_BRANCH_SHA,
// ${CI_MERGE_REQUEST_SOURCE_BRANCH_SHA}, case sensitive) and in PowerShell
// form ($env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA,
// ${env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA}), where variable names are case
// insensitive, so the env: prefix and the variable name match in any case. A
// lowercase POSIX reference ($ci_merge_request_source_branch_sha) is a
// different variable and does not match.
var mrSourceSHARe = regexp.MustCompile(`\$\{?CI_MERGE_REQUEST_SOURCE_BRANCH_SHA\}?|\$(?i:\{?env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA\}?)`)

func (r *gl044) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !in.Has(job, "rules") && !in.Has(job, "only") {
			return
		}
		job = in.Effective(job)
		if !jobHasMRTrigger(job) {
			return
		}

		jobScripts := []*yaml.Node{
			parser.FindKey(job, "script"),
			parser.FindKey(job, "before_script"),
		}
		jobScripts = append(jobScripts, parser.RunStepBlocks(job)...)
		for _, node := range jobScripts {
			if node == nil {
				continue
			}
			for _, f := range checkScriptForMRSourceSHA(node, file) {
				f.Job = name.Value
				findings = append(findings, f)
			}
		}
		if h := hookScriptNode(job); h != nil {
			for _, f := range checkScriptForMRSourceSHA(h, file) {
				f.Job = name.Value
				findings = append(findings, f)
			}
		}

		if imageNode := parser.FindKey(job, "image"); imageNode != nil {
			if f := checkImageForMRSourceSHA(imageNode, file, name.Value); f != nil {
				findings = append(findings, *f)
			}
		}
	})

	return findings
}

// jobHasMRTrigger returns true if the job is triggered on merge request events,
// either via the legacy only: syntax or via rules:if conditions.
func jobHasMRTrigger(job *yaml.Node) bool {
	if onlyNode := parser.FindKey(job, "only"); onlyNode != nil && onlyNode.Kind == yaml.SequenceNode {
		for _, item := range onlyNode.Content {
			if item.Kind == yaml.ScalarNode && item.Value == "merge_requests" {
				return true
			}
		}
	}

	rulesNode := parser.FindKey(job, "rules")
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rulesNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
			continue
		}
		if strings.Contains(ifNode.Value, "merge_request") {
			return true
		}
	}
	return false
}

func checkScriptForMRSourceSHA(node *yaml.Node, file string) []finding.Finding {
	if !isScriptList(node) {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if loc := mrSourceSHARe.FindStringIndex(item.Value); loc != nil {
			line, col := scriptMatchPos(item, loc[0])
			findings = append(findings, finding.Finding{
				RuleID:   "GL044",
				Severity: finding.Warn,
				Message:  "MR-triggered job checks out $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA — executes attacker-controlled code with access to $CI_JOB_TOKEN and protected variables",
				File:     file,
				Line:     line,
				Col:      col,
			})
		}
	}
	return findings
}

func checkImageForMRSourceSHA(node *yaml.Node, file, job string) *finding.Finding {
	var imageValue string
	switch node.Kind {
	case yaml.ScalarNode:
		imageValue = node.Value
	case yaml.MappingNode:
		if nameNode := parser.FindKey(node, "name"); nameNode != nil && nameNode.Kind == yaml.ScalarNode {
			imageValue = nameNode.Value
			node = nameNode
		}
	}
	if !mrSourceSHARe.MatchString(imageValue) {
		return nil
	}
	f := finding.Finding{
		RuleID:   "GL044",
		Severity: finding.Warn,
		Job:      job,
		Message:  "MR-triggered job uses $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA in image: — pulls an attacker-controlled container image",
		File:     file,
		Line:     node.Line,
		Col:      node.Column,
	}
	return &f
}
