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

type gl015 struct{}

var GL015 = &gl015{}

func (r *gl015) ID() string { return "GL015" }

var (
	// dockerCmdRe matches docker or podman build/push/tag/buildx commands.
	dockerCmdRe = mustCompilePrefiltered(`\b(?:docker|podman)\s+(?:build|push|tag|buildx)\b`)

	// userControlledTagRe matches an image tag that uses a user-controlled variable,
	// i.e. a colon (tag separator) followed by a user-controlled predefined variable.
	// CI_COMMIT_SHA, CI_PIPELINE_ID, and CI_COMMIT_SHORT_SHA are safe — not listed here.
	userControlledTagRe = mustCompilePrefiltered(
		`:\$\{?(CI_COMMIT_REF_NAME|CI_COMMIT_REF_SLUG|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?`,
	)
)

func (r *gl015) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	// A job restricted to the default branch or a protected ref can only run
	// with the ref variable pinned to that branch (e.g. master), so a fork
	// contributor can't steer the tag; such jobs are exempt (#1103). Gating to
	// tags: does not mitigate — tags are user-creatable — so gl046ProtectedOnly,
	// which matches only default/protected-branch conditions, is the right test.
	in := NewInheritance(doc)
	protectedOnly := map[string]bool{}
	extenders := map[string][]string{}
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		protectedOnly[name.Value] = gl015Pinned(in.Effective(job))
		if !strings.HasPrefix(name.Value, ".") {
			for _, base := range in.extendsAncestors(job) {
				extenders[base] = append(extenders[base], name.Value)
			}
		}
	})
	// A hidden template never runs itself: it is as pinned as every job that
	// extends it (#1526). One without extenders in the file is a library
	// template and stays reported.
	for base, jobs := range extenders {
		if !strings.HasPrefix(base, ".") {
			continue
		}
		pinned := true
		for _, j := range jobs {
			pinned = pinned && protectedOnly[j]
		}
		protectedOnly[base] = pinned
	}

	aliases := newUserAliases(doc)
	EachScriptLine(doc, file, func(item *yaml.Node, file, job string) {
		if protectedOnly[job] {
			return
		}
		if !dockerCmdRe.MatchString(item.Value) {
			return
		}
		// An image name held in a variable that references a user-controlled
		// one is user-controlled too (#1504).
		text, used := aliases.expand(item.Value, job)
		for _, cmd := range shellCommands(text) {
			varName := ""
			for _, t := range writtenImageRefs(commandWords(cmd.text)) {
				// The name from the group: ${NAME//x/y} or ${NAME:-d} has no } right after it (#977).
				// A per-run value in the reference makes the tag one no other
				// pipeline writes, so it can't overwrite a shared one (#1526).
				if m := userControlledTagRe.FindStringSubmatch(t); m != nil && !mentionsPerRunValue(t) {
					varName = m[1]
					break
				}
			}
			if varName == "" {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL015",
				Severity: finding.Warn,
				Job:      job,
				Message: fmt.Sprintf(
					"Docker image tag uses user-controlled variable $%s — a branch named \"latest\" or \"main\" overwrites the production tag; use $CI_COMMIT_SHA instead",
					varName,
				),
				File: file,
				Line: parser.ScalarContentLine(item, cmd.line),
			}
			if cmd.line == 0 {
				f.Col = item.Column
			}
			if used != nil && !mentionsVar(item.Value, varName) {
				f.Message += aliasNote(used)
			}
			findings = append(findings, f)
		}
	})
	return findings
}

// writtenImageRefs returns the image references a docker/podman command
// writes: the -t/--tag values of build, the target of tag, the image of push.
// The source of `docker tag` and values such as --label are only read.
func writtenImageRefs(words []string) []string {
	if name := commandName(words); name != "docker" && name != "podman" || len(words) < 2 {
		return nil
	}
	args := words[1:]
	if args[0] == "buildx" || args[0] == "image" {
		args = args[1:]
	}
	if len(args) > 1 && args[0] == "imagetools" && args[1] == "create" {
		args = append([]string{"build"}, args[2:]...) // writes its -t tags like build
	}
	if len(args) == 0 {
		return nil
	}
	sub, args := args[0], args[1:]
	var positional, tags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t" || a == "--tag":
			if i+1 < len(args) {
				tags = append(tags, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--tag="):
			tags = append(tags, strings.TrimPrefix(a, "--tag="))
		case strings.HasPrefix(a, "-t") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			tags = append(tags, a[2:])
		case strings.HasPrefix(a, "-"):
		default:
			positional = append(positional, a)
		}
	}
	switch sub {
	case "build":
		return tags
	case "tag":
		if len(positional) > 0 {
			return positional[len(positional)-1:]
		}
	case "push":
		return positional
	}
	return nil
}

// perRunValueVars are predefined variables whose value is new on every run.
var perRunValueVars = []string{"CI_COMMIT_SHA", "CI_COMMIT_SHORT_SHA", "CI_PIPELINE_ID", "CI_PIPELINE_IID", "CI_JOB_ID"}

func mentionsPerRunValue(ref string) bool {
	for _, name := range ciVarNames(ref) {
		for _, v := range perRunValueVars {
			if name == v {
				return true
			}
		}
	}
	return false
}

// gl015Pinned reports a job whose ref variable can only hold names the file
// fixes: the default branch or a protected ref (gl046ProtectedOnly), or any
// branch named literally (#1526), through only: names or refs:, or rules: on
// $CI_COMMIT_BRANCH == "name". A fork contributor can't pick the name then.
// $CI_COMMIT_REF_NAME is not read for a named branch: in a merge request
// pipeline it holds the source branch's name.
func gl015Pinned(job *yaml.Node) bool {
	if gl046ProtectedOnly(job) {
		return true
	}
	if only := parser.FindKey(job, "only"); only != nil {
		if only.Kind == yaml.MappingNode {
			only = parser.FindKey(only, "refs")
		}
		if only == nil || only.Kind != yaml.SequenceNode || len(only.Content) == 0 {
			return false
		}
		for _, item := range only.Content {
			if !literalBranchName(item.Value) {
				return false
			}
		}
		return true
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	running := 0
	for _, item := range rules.Content {
		if when := parser.FindKey(item, "when"); when != nil && when.Value == "never" {
			continue
		}
		cond := parser.FindKey(item, "if")
		if cond == nil {
			return false
		}
		for _, branch := range strings.Split(cond.Value, "||") {
			if !protectedRefCondRe.MatchString(branch) && !namedBranchCondRe.MatchString(branch) {
				return false
			}
		}
		running++
	}
	return running > 0
}

var namedBranchCondRe = mustCompilePrefiltered(`\$\{?CI_COMMIT_BRANCH\}?\s*==\s*(?:"[^"$]+"|'[^'$]+')`)

func literalBranchName(v string) bool {
	return v != "" && !onlyKeywords[v] && !strings.HasPrefix(v, "/") && !strings.ContainsAny(v, "$*@")
}

// extendsAncestors returns the names of the jobs job extends in this file,
// directly or through other templates.
func (in *Inheritance) extendsAncestors(job *yaml.Node) []string {
	var out []string
	seen := map[*yaml.Node]bool{}
	var walk func(j *yaml.Node, depth int)
	walk = func(j *yaml.Node, depth int) {
		if j == nil || j.Kind != yaml.MappingNode || seen[j] || depth > maxExtendsDepth {
			return
		}
		seen[j] = true
		ext := parser.FindKey(j, "extends")
		if ext == nil {
			return
		}
		parents := []*yaml.Node{ext}
		if ext.Kind == yaml.SequenceNode {
			parents = ext.Content
		}
		for _, p := range parents {
			if p.Kind == yaml.ScalarNode {
				out = append(out, p.Value)
				walk(in.jobs[p.Value], depth+1)
			}
		}
	}
	walk(job, 0)
	return out
}
