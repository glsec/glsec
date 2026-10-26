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

type gl017 struct{}

var GL017 = &gl017{}

func (r *gl017) ID() string { return "GL017" }

// deployStageKeywords identifies stages that indicate deployment activity.
var deployStageKeywords = []string{"deploy", "release", "publish", "ship"}

func (r *gl017) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !runsInheritedJob(in, name, job) || !isSensitiveJob(in, job) {
			return
		}
		// A trigger job starts a downstream pipeline and runs on no runner, so
		// tags: has nothing to restrict there.
		if in.Key(job, "trigger") != nil {
			return
		}
		tagsNode := in.Key(job, "tags")
		if tagsNode != nil && tagsNode.Kind == yaml.SequenceNode && len(tagsNode.Content) > 0 {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL017",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"job %q deploys or publishes but has no tags: — it can run on any available runner, including untrusted self-hosted runners",
				name.Value,
			),
			File: file,
			Line: name.Line,
			Col:  name.Column,
		})
	})

	return findings
}

// isSensitiveJob returns true for jobs that deploy to an environment or
// whose stage name suggests deployment/release activity.
// runsInheritedJob reports whether a job is one GitLab runs and whose
// inherited keys are all visible here: not a hidden template, and not
// extending a template from another file.
func runsInheritedJob(in *Inheritance, name, job *yaml.Node) bool {
	return !strings.HasPrefix(name.Value, ".") && in.ExtendsResolved(job)
}

func isSensitiveJob(in *Inheritance, job *yaml.Node) bool {
	if in.Key(job, "environment") != nil {
		return true
	}
	stageNode := in.Key(job, "stage")
	if stageNode != nil && stageNode.Kind == yaml.ScalarNode {
		lower := strings.ToLower(stageNode.Value)
		for _, kw := range deployStageKeywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
	}
	return false
}
