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

type gl017 struct{}

var GL017 = &gl017{}

func (r *gl017) ID() string { return "GL017" }

// deployStageKeywords identifies stages that indicate deployment activity.
var deployStageKeywords = []string{"deploy", "release", "publish", "ship"}

func (r *gl017) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !runsInheritedJob(in, name, job) || !isSensitiveJob(in, job, true) {
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
// envActionNoDeploy reports an environment: whose action deploys nothing:
// prepare, verify and access only use the environment.
func envActionNoDeploy(env *yaml.Node) bool {
	if env.Kind != yaml.MappingNode {
		return false
	}
	a := parser.FindKey(env, "action")
	return a != nil && (a.Value == "prepare" || a.Value == "verify" || a.Value == "access")
}

// envDevTier reports an environment that declares itself a review or test
// target: per-branch previews, links to job artifacts.
func envDevTier(env *yaml.Node) bool {
	t, _ := envTier(env)
	return t == "development" || t == "testing"
}

// envTier returns an environment's deployment tier: its deployment_tier:,
// else the tier GitLab guesses from the name (Environment#guess_tier in
// GitLab's source, #989). explicit reports which.
func envTier(env *yaml.Node) (tier string, explicit bool) {
	name := ""
	switch env.Kind {
	case yaml.ScalarNode:
		name = env.Value
	case yaml.MappingNode:
		if t := parser.FindKey(env, "deployment_tier"); t != nil && t.Kind == yaml.ScalarNode {
			return t.Value, true
		}
		if n := parser.FindKey(env, "name"); n != nil && n.Kind == yaml.ScalarNode {
			name = n.Value
		}
	}
	for _, g := range tierGuesses {
		if g.re.MatchString(name) {
			return g.tier, false
		}
	}
	return "other", false
}

// tierGuesses are GitLab's guesses, in its order: a name matches the first.
var tierGuesses = []struct {
	tier string
	re   *regexp.Regexp
}{
	{"development", regexp.MustCompile(`(?i)(dev|review|trunk)`)},
	{"testing", regexp.MustCompile(`(?i)(test|tst|int|ac(ce|)pt|qa|qc|control|quality)`)},
	{"staging", regexp.MustCompile(`(?i)(st(a|)g|mod(e|)l|pre|demo|non)`)},
	{"production", regexp.MustCompile(`(?i)(pr(o|)d|live)`)},
}

// checkOnlyKeywords mark a job or stage that tests or checks rather than
// deploys, whatever else its name says: "deployment test", "check
// migrations", "release/gitleaks-scan".
var checkOnlyKeywords = []string{"test", "lint", "check", "coverage", "validate", "audit", "scan", "note", "changelog", "cleanup"}

// buildKeywords mark a build. They outweigh the weaker deploy words
// (release-build, assembleRelease, build-migrations), not push, publish or
// deploy: build-and-push still publishes.
var buildKeywords = []string{"build", "compile", "assemble"}

// strongDeployKeywords name the act of shipping something.
var strongDeployKeywords = []string{"deploy", "publish", "push", "upload", "rollout", "ship"}

// deployLikeName reports whether a job or stage name (lower case) says it
// deploys, given the keywords that count for the caller.
func deployLikeName(lower string, keywords []string) bool {
	if hasWordPrefix(lower, checkOnlyKeywords) {
		return false
	}
	if !containsAny(lower, keywords) {
		return false
	}
	return containsAny(lower, strongDeployKeywords) || !containsAny(lower, buildKeywords)
}

// hasWordPrefix reports whether a word of s (split at anything that is not a
// letter or digit) starts with one of words: "k8s-test" and "linting" match
// test and lint, "latest" doesn't.
func hasWordPrefix(s string, words []string) bool {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		for _, w := range words {
			if strings.HasPrefix(tok, w) {
				return true
			}
		}
	}
	return false
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// runsInheritedJob reports whether a job is one GitLab runs and whose
// inherited keys are all visible here: not a hidden template, and not
// extending a template from another file.
func runsInheritedJob(in *Inheritance, name, job *yaml.Node) bool {
	return !strings.HasPrefix(name.Value, ".") && in.ExtendsResolved(job) && !in.IncludedOverride(job)
}

// isSensitiveJob reports a job that deploys through its environment: or its
// stage. With devTierDeploys false, an environment whose deployment_tier is
// development or testing doesn't count as a deploy (#797).
func isSensitiveJob(in *Inheritance, job *yaml.Node, devTierDeploys bool) bool {
	// An environment: deploys unless its action only uses the environment;
	// then the stage still decides.
	if env := in.Key(job, "environment"); env != nil && !envActionNoDeploy(env) && (devTierDeploys || !envDevTier(env)) {
		return true
	}
	stageNode := in.Key(job, "stage")
	if stageNode != nil && stageNode.Kind == yaml.ScalarNode {
		return deployLikeName(strings.ToLower(stageNode.Value), deployStageKeywords)
	}
	return false
}
