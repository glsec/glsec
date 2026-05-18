package rules

import (
	"regexp"

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

	// newBranchFlagRe detects -b or --orphan (creates a local branch, not a dep checkout).
	newBranchFlagRe = regexp.MustCompile(`\s(?:-b|--orphan)(?:\s|$)`)
)

func (r *gl026) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)
		if len(lines) == 0 {
			return
		}

		// Pre-check: does the job have any SHA-pinned checkout?
		// A bare `git clone` paired with `git checkout <sha>` is the safe pattern.
		hasSHACheckout := false
		for _, l := range lines {
			if gitCheckoutRe.MatchString(l.Value) && shaRe.MatchString(l.Value) {
				hasSHACheckout = true
				break
			}
		}

		for _, l := range lines {
			line := l.Value

			if gitCloneRe.MatchString(line) {
				m := branchFlagRe.FindStringSubmatch(line)
				if len(m) >= 2 {
					ref := m[1]
					if !shaRe.MatchString(ref) {
						findings = append(findings, finding.Finding{
							RuleID:   "GL026",
							Severity: finding.Warn,
							Job:      name.Value,
							Message:  "git clone uses mutable ref \"" + ref + "\" — pin to a full commit SHA with git checkout after cloning",
							File:     file,
							Line:     l.Line,
							Col:      l.Column,
						})
					}
				} else if !hasSHACheckout {
					findings = append(findings, finding.Finding{
						RuleID:   "GL026",
						Severity: finding.Warn,
						Job:      name.Value,
						Message:  "git clone without --branch clones HEAD of the default branch — follow with git checkout <sha> to pin the revision",
						File:     file,
						Line:     l.Line,
						Col:      l.Column,
					})
				}
				continue
			}

			if gitCheckoutRe.MatchString(line) {
				if newBranchFlagRe.MatchString(line) {
					continue // creating a local branch, not a dependency checkout
				}
				if shaRe.MatchString(line) {
					continue // SHA-pinned — safe
				}
				findings = append(findings, finding.Finding{
					RuleID:   "GL026",
					Severity: finding.Warn,
					Job:      name.Value,
					Message:  "git checkout uses a mutable ref — pin to a full 40-character commit SHA",
					File:     file,
					Line:     l.Line,
					Col:      l.Column,
				})
			}
		}
	})

	return findings
}
