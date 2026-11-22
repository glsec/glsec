// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
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
var mrSourceSHARe = mustCompilePrefiltered(`\$\{?CI_MERGE_REQUEST_SOURCE_BRANCH_SHA\}?|\$(?i:\{?env:CI_MERGE_REQUEST_SOURCE_BRANCH_SHA\}?)`)

// mrSourceNameRe matches a reference to CI_MERGE_REQUEST_SOURCE_BRANCH_NAME in
// the same POSIX and PowerShell env: forms as mrSourceSHARe. The name resolves
// to the live tip of the merge request source branch, so a checkout of it runs
// attacker-controlled code just as the SHA does — and is not even pinned to the
// reviewed commit. TARGET branch and DIFF_BASE variables are not matched: they
// are not attacker-controlled.
var mrSourceNameRe = mustCompilePrefiltered(`\$\{?CI_MERGE_REQUEST_SOURCE_BRANCH_NAME\}?|\$(?i:\{?env:CI_MERGE_REQUEST_SOURCE_BRANCH_NAME\}?)`)

// matchesMRSource reports whether s references the merge request source branch
// in either its SHA or its NAME form.
func matchesMRSource(s string) bool {
	return mrSourceSHARe.MatchString(s) || mrSourceNameRe.MatchString(s)
}

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
		// A job confined to merge requests from a branch in this project
		// (source project == this project) never runs for a fork, so its
		// source branch is not attacker-controlled.
		if jobRestrictedToSameProjectMR(job) {
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
			for _, f := range checkScriptForMRSource(node, file) {
				f.Job = name.Value
				findings = append(findings, f)
			}
		}
		if h := hookScriptNode(job); h != nil {
			for _, f := range checkScriptForMRSource(h, file) {
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

// mrForkGuardRe matches a rules:if comparison that confines a job to merge
// requests whose source branch lives in this project (source project == this
// project), in either operand order. CI_MERGE_REQUEST_SOURCE_PROJECT_* is the
// fork's project; comparing it equal to CI_PROJECT_* or
// CI_MERGE_REQUEST_PROJECT_* means "not a fork".
var mrForkGuardRe = mustCompilePrefiltered(
	`CI_MERGE_REQUEST_SOURCE_PROJECT_(?:PATH|ID|URL)\b[}"' ]*==[ $={"']*CI_(?:MERGE_REQUEST_)?PROJECT_(?:PATH|ID|URL)\b` +
		`|CI_(?:MERGE_REQUEST_)?PROJECT_(?:PATH|ID|URL)\b[}"' ]*==[ $={"']*CI_MERGE_REQUEST_SOURCE_PROJECT_(?:PATH|ID|URL)\b`)

// jobRestrictedToSameProjectMR reports whether an allow rule confines the job
// to same-project merge requests (so forks never reach it). A `when: never`
// rule carrying the guard is the dangerous inverse — it excludes same-project
// MRs and leaves forks — so it does not count.
func jobRestrictedToSameProjectMR(job *yaml.Node) bool {
	rulesNode := parser.FindKey(job, "rules")
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rulesNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode || !mrForkGuardRe.MatchString(ifNode.Value) {
			continue
		}
		if whenNode := parser.FindKey(item, "when"); whenNode != nil && whenNode.Value == "never" {
			continue
		}
		return true
	}
	return false
}

func checkScriptForMRSource(node *yaml.Node, file string) []finding.Finding {
	if !isScriptList(node) {
		return nil
	}
	var findings []finding.Finding
	fetched := false
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if at, ok := checksOutMRSource(item.Value, &fetched); ok {
			line, col := scriptLinePos(item, at)
			findings = append(findings, finding.Finding{
				RuleID:   "GL044",
				Severity: finding.Warn,
				Message:  "MR-triggered job checks out the merge request source branch — executes attacker-controlled code with access to $CI_JOB_TOKEN and protected variables",
				File:     file,
				Line:     line,
				Col:      col,
			})
		}
	}
	return findings
}

// gitCheckoutSubcommands are the git subcommands that put a revision in the
// working tree. Reading history with the SHA (git log, rev-list, diff,
// commitlint --to) checks out nothing (#980).
var gitCheckoutSubcommands = map[string]bool{"checkout": true, "switch": true, "reset": true, "restore": true, "worktree": true}

// checksOutMRSource reports whether a script item checks out the MR source
// branch (SHA or NAME form), directly or through FETCH_HEAD after an earlier
// item fetched it (*fetched carries that across items), and the index of the
// item line that does. A fetch of another ref, such as the target branch,
// repoints FETCH_HEAD and clears *fetched, so a later checkout FETCH_HEAD of
// the target is not reported.
func checksOutMRSource(item string, fetched *bool) (int, bool) {
	if !*fetched && !matchesMRSource(item) {
		return 0, false
	}
	for _, cmd := range shellCommands(item) {
		args, _ := gitArgs(commandWords(cmd.text))
		if len(args) == 0 {
			continue
		}
		sub := args[0]
		hasSource := matchesMRSource(cmd.text)
		switch {
		case sub == "fetch":
			*fetched = hasSource
		case gitCheckoutSubcommands[sub] && (hasSource || *fetched && strings.Contains(cmd.text, "FETCH_HEAD")):
			return cmd.line, true
		}
	}
	return 0, false
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
