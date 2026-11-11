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
	// A global default: interruptible is one shared node; every job that inherits
	// it resolves to the same line, so anchoring the finding there would collapse
	// several deploy jobs into one (findings are de-duplicated by location).
	// Anchor those at the job instead, so each affected job is reported (#1396).
	var defaultInterruptible *yaml.Node
	if def := parser.FindKey(parser.Unwrap(doc), "default"); def != nil {
		defaultInterruptible = parser.FindKey(def, "interruptible")
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// A job extending a template from another file still counts: its own
		// keys win over anything that template sets.
		if strings.HasPrefix(name.Value, ".") || !deployLikeInherited(in, name.Value, job) {
			return
		}
		interruptible := in.Key(job, "interruptible")
		if !parser.IsTrue(interruptible) {
			return
		}
		// A job disabled by rules: all when: never never runs, so a mid-run
		// cancellation can't leave an environment half-updated (#1104).
		if rules := in.Key(job, "rules"); rules != nil && rules.Kind == yaml.SequenceNode && onlyNever(rules) {
			return
		}
		line, col := interruptible.Line, interruptible.Column
		if interruptible == defaultInterruptible {
			line, col = name.Line, name.Column
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
			Line: line,
			Col:  col,
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
		if checkStage {
			return false
		}
		// A deploy-like stage together with a deploy-like name is signal enough
		// (run migrations in stage: deploy), so the script is not consulted.
		deployStage := stage != nil && stage.Kind == yaml.ScalarNode &&
			deployLikeName(strings.ToLower(stage.Value), deployLikeKeywords)
		lowerName := strings.ToLower(jobName)
		// Outside a deploy stage, a job whose only deploy signal is an
		// artifact-building word (release, dist) or a dry run usually just
		// builds or packages an artifact without shipping it — a tarball, an
		// sdist, an APK, a `make release`, an empty timer gate — so it counts
		// only when its script actually deploys (#1372, generalizing the
		// build-stage guard of #1104/#1385 to build, test and unstaged jobs). A
		// strong keyword (deploy, publish, push, …) or a deploy-action word
		// (migrate, provision) names the deployment itself and decides alone.
		if !deployStage && !containsAny(lowerName, strongDeployKeywords) &&
			!containsAny(lowerName, deployActionWeakKeywords) &&
			(dryRunName(lowerName) || containsAny(lowerName, artifactWeakKeywords)) {
			return jobScriptDeploys(in, job)
		}
		return true
	}
	if stage := in.Key(job, "stage"); stage != nil && stage.Kind == yaml.ScalarNode &&
		deployLikeName(strings.ToLower(stage.Value), deployLikeKeywords) {
		// A deploy/release/dist-named stage alone over-fires on build-only jobs
		// that only produce an artifact (meson dist, cargo build). Classified by
		// stage alone, require the script to actually deploy or publish (#1104,
		// mirroring the GL017/GL019 guard in #1096).
		return jobScriptDeploys(in, job)
	}
	return false
}

// artifactWeakKeywords name jobs that usually build or package an artifact (a
// release tarball, an sdist) and only sometimes ship it, so a name match alone
// over-reports (#1372). deployActionWeakKeywords name the deployment action
// itself (a database migration, infrastructure provisioning), which the name
// settles without reading the script.
var (
	artifactWeakKeywords     = []string{"release", "dist"}
	deployActionWeakKeywords = []string{"migrat", "provision"}
)

// dryRunName reports a job name with the words dry run (release_dry_run,
// release-dryrun), whose job rehearses a release without changing anything.
func dryRunName(lower string) bool {
	words := strings.FieldsFunc(lower, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	for i, w := range words {
		if w == "dryrun" || (w == "dry" && i+1 < len(words) && words[i+1] == "run") {
			return true
		}
	}
	return false
}
