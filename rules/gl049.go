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

type gl049 struct{}

var GL049 = &gl049{}

func (r *gl049) ID() string { return "GL049" }

func (r *gl049) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// A job extending a template from another file still counts: its own
		// keys win over anything that template sets.
		if strings.HasPrefix(name.Value, ".") || !deployLikeInherited(in, name.Value, job) {
			return
		}
		interruptible := in.Key(job, "interruptible")
		if interruptible == nil || interruptible.Kind != yaml.ScalarNode {
			return
		}
		if strings.ToLower(interruptible.Value) != "true" {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL049",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"deploy job %q has interruptible: true — a mid-run cancellation leaves the target environment in an undefined state; set interruptible: false or omit it (default is false)",
				name.Value,
			),
			File: file,
			Line: interruptible.Line,
			Col:  interruptible.Column,
		})
	})

	return findings
}

// deployLikeInherited is IsDeployLikeJob over the keys the job inherits, with
// a development or testing environment not counting as a deploy (#797).
// A job whose only deploy signal is a name keyword and whose stage is a
// check-only stage (#820, e.g. a fuzz job named after migrations in
// stage: test) is not a deploy job: the stage says what the job does.
// A job with an environment: or a deploy-like stage still counts, as do
// name-keyword jobs in any other stage.
func deployLikeInherited(in *Inheritance, jobName string, job *yaml.Node) bool {
	// GitLab Pages deploys the site only after the job succeeds, so a
	// cancelled pages job leaves the old site in place (#981).
	if jobName == "pages" || in.Key(job, "pages") != nil {
		return false
	}
	stage := in.Key(job, "stage")
	checkStage := stage != nil && stage.Kind == yaml.ScalarNode && hasWordPrefix(strings.ToLower(stage.Value), checkOnlyKeywords)
	if env := in.Key(job, "environment"); env != nil && !envActionNoDeploy(env) && !envDevTier(env) {
		// An environment with neither a tier nor a name GitLab reads as
		// production or staging doesn't make a job in a test stage a deploy.
		if tier, _ := envTier(env); tier == "other" && checkStage {
			return false
		}
		return true
	}
	if deployLikeName(strings.ToLower(jobName), deployLikeKeywords) {
		if stage := in.Key(job, "stage"); stage != nil && stage.Kind == yaml.ScalarNode &&
			hasWordPrefix(strings.ToLower(stage.Value), checkOnlyKeywords) {
			return false
		}
		return true
	}
	if stage := in.Key(job, "stage"); stage != nil && stage.Kind == yaml.ScalarNode {
		return deployLikeName(strings.ToLower(stage.Value), deployLikeKeywords)
	}
	return false
}
