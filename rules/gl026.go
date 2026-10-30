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

type gl026 struct{}

var GL026 = &gl026{}

func (r *gl026) ID() string { return "GL026" }

var (
	// shaRe matches a full 40-character lowercase hex commit SHA.
	shaRe = regexp.MustCompile(`[0-9a-f]{40}`)

	// gitCloneRe matches a git clone invocation (handles git -C <dir> clone too).
	gitCloneRe = regexp.MustCompile(`\bgit\b[^|;&]*\bclone\b`)

	// gitCheckoutRe matches a git checkout invocation.
	gitCheckoutRe = regexp.MustCompile(`\bgit\b[^|;&]*\bcheckout\b`)

	// branchFlagRe captures the value of --branch or -b.
	// Handles both space-separated (--branch main) and equals-sign (--branch=main) forms.
	branchFlagRe = regexp.MustCompile(`(?:--branch|-b)(?:\s+|=)(\S+)`)
)

// shaVarRe matches a predefined variable that holds a commit SHA, such as
// $CI_COMMIT_SHA, ${CI_MERGE_REQUEST_DIFF_BASE_SHA} or the deprecated
// $CI_BUILD_REF: immutable like a literal SHA.
var shaVarRe = regexp.MustCompile(`^\$\{?(?:CI_[A-Z_]*_SHA|CI_BUILD_REF)\}?$`)

// checksOutMutableRef reports whether a command is `git checkout <ref>` with a
// ref other than a commit SHA. Creating a local branch (-b, -B, --orphan) and
// restoring files (git checkout -- path, git checkout <ref> -- path,
// git checkout .) are not ref checkouts, and neither are other subcommands
// that only contain the word (git submodule update --checkout, git lfs
// checkout, git config checkout.defaultRemote).
func checksOutMutableRef(words []string) bool {
	if commandName(words) != "git" {
		return false
	}
	args := words[1:]
	// Global options before the subcommand: -C dir, -c key=value, --git-dir=….
	// With -C or --git-dir the checkout may be in another repository.
	otherRepo := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		if args[0] == "-C" || strings.HasPrefix(args[0], "--git-dir") || strings.HasPrefix(args[0], "--work-tree") {
			otherRepo = true
		}
		if (args[0] == "-C" || args[0] == "-c") && len(args) > 1 {
			args = args[1:]
		}
		args = args[1:]
	}
	if len(args) == 0 || args[0] != "checkout" {
		return false
	}
	var refs []string
	for _, a := range args[1:] {
		switch {
		case a == "-b" || a == "-B" || a == "--orphan" || a == "--":
			return false
		case strings.HasPrefix(a, "-"):
		default:
			refs = append(refs, a)
		}
	}
	if len(refs) == 0 || refs[0] == "." || len(refs) > 1 {
		return false // no ref, or files: git checkout . / git checkout file1 file2
	}
	if !otherRepo && ownBranchVarRe.MatchString(refs[0]) {
		return false
	}
	return !shaRe.MatchString(refs[0]) && !shaVarRe.MatchString(refs[0])
}

// ownBranchVarRe matches a branch of the project the pipeline runs for,
// optionally on the origin remote. Checking it out in the project's own
// clone brings in no third-party code (#984).
var ownBranchVarRe = regexp.MustCompile(`^["']?(?:origin/)?\$\{?(?:CI_DEFAULT_BRANCH|CI_COMMIT_REF_NAME|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME|CI_MERGE_REQUEST_TARGET_BRANCH_NAME)\}?["']?$`)

// ownRepoSourceRe matches a clone source that is the project's own
// repository: the checkout (., $CI_PROJECT_DIR) or its remote
// ($CI_REPOSITORY_URL).
var ownRepoSourceRe = regexp.MustCompile(`^(?:\.|\./|\$\{?CI_PROJECT_DIR\}?|\$\{?CI_REPOSITORY_URL\}?)$`)

// localCloneSource reports whether a git clone copies the project's own
// repository.
func localCloneSource(words []string) bool {
	seenClone := false
	for i := 1; i < len(words); i++ {
		w := strings.Trim(words[i], `"'`)
		switch {
		case !seenClone:
			seenClone = w == "clone"
		case w == "-b" || w == "--branch" || w == "--depth" || w == "-o" || w == "--origin" || w == "-c" || w == "--config":
			i++
		case strings.HasPrefix(w, "-"):
		default:
			return ownRepoSourceRe.MatchString(w)
		}
	}
	return false
}

func (r *gl026) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	// What each line says on its own, cached for lines shared through an
	// anchor (#766). Only the bare-clone finding depends on the job.
	facts := nodeMemo[gl026Facts]{}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)
		if len(lines) == 0 {
			return
		}
		all := make([]gl026Facts, len(lines))
		// A bare `git clone` paired with `git checkout <sha>` is the safe pattern.
		hasSHACheckout := false
		for i, l := range lines {
			all[i] = facts.get(l, func() gl026Facts { return gl026Line(l, file) })
			hasSHACheckout = hasSHACheckout || all[i].shaCheckout
		}
		for i, l := range lines {
			for _, f := range all[i].findings {
				f.Job = name.Value
				findings = append(findings, f)
			}
			if all[i].bareClone && !hasSHACheckout {
				ln, col := scriptMatchPos(l, all[i].cloneAt)
				findings = append(findings, finding.Finding{
					RuleID:   "GL026",
					Severity: finding.Warn,
					Job:      name.Value,
					Message:  "git clone without --branch clones HEAD of the default branch — follow with git checkout <sha> to pin the revision",
					File:     file,
					Line:     ln,
					Col:      col,
				})
			}
		}
	})

	return findings
}

// gl026Facts is what one script item says on its own.
type gl026Facts struct {
	shaCheckout bool              // checks out a commit SHA
	bareClone   bool              // git clone without --branch
	cloneAt     int               // byte offset of the git clone in the item
	findings    []finding.Finding // the findings that don't depend on the job, without Job
}

// gl026Line checks one script item.
func gl026Line(l *yaml.Node, file string) (lf gl026Facts) {
	line := l.Value
	lf.shaCheckout = gitCheckoutRe.MatchString(line) && shaRe.MatchString(line)
	if loc := gitCloneRe.FindStringIndex(line); loc != nil {
		for _, cmd := range shellCommands(line) {
			if words := commandWords(cmd.text); commandName(words) == "git" && localCloneSource(words) {
				return lf
			}
		}
		lf.cloneAt = loc[0]
		ln, col := scriptMatchPos(l, loc[0])
		m := branchFlagRe.FindStringSubmatch(line)
		switch {
		case len(m) < 2:
			lf.bareClone = true
		case !shaRe.MatchString(m[1]):
			lf.findings = append(lf.findings, finding.Finding{
				RuleID:   "GL026",
				Severity: finding.Warn,
				Message:  "git clone uses mutable ref \"" + strings.Trim(m[1], `"'`) + "\" — pin to a full commit SHA with git checkout after cloning",
				File:     file,
				Line:     ln,
				Col:      col,
			})
		}
		return lf
	}
	if gitCheckoutRe.MatchString(line) {
		for _, cmd := range shellCommands(line) {
			if !checksOutMutableRef(commandWords(cmd.text)) {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL026",
				Severity: finding.Warn,
				Message:  "git checkout uses a mutable ref — pin to a full 40-character commit SHA",
				File:     file,
				Line:     parser.ScalarContentLine(l, cmd.line),
			}
			if cmd.line == 0 {
				f.Col = l.Column
			}
			lf.findings = append(lf.findings, f)
		}
	}
	return lf
}
