package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl025 struct{}

var GL025 = &gl025{}

func (r *gl025) ID() string { return "GL025" }

// userControlledVarRe matches any of the CI variables an attacker can influence
// via branch name, MR title, commit message, etc.
var userControlledVarRe = regexp.MustCompile(
	`\$\{?CI_(?:COMMIT_REF_NAME|COMMIT_REF_SLUG|COMMIT_BRANCH|COMMIT_TAG|COMMIT_MESSAGE|COMMIT_TITLE|COMMIT_DESCRIPTION|MERGE_REQUEST_SOURCE_BRANCH_NAME|MERGE_REQUEST_TITLE)\}?`,
)

// curlWgetRe matches curl or wget invocations.
var curlWgetRe = regexp.MustCompile(`\b(?:curl|wget)\b`)

func (r *gl025) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, l := range collectScriptLines(job) {
			if !curlWgetRe.MatchString(l.Value) {
				continue
			}
			m := userControlledVarRe.FindString(l.Value)
			if m == "" {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL025",
				Severity: finding.Warn,
				Job:      name.Value,
				Message:  "curl/wget uses user-controlled variable " + m + " — attacker can redirect the request to an arbitrary host",
				File:     file,
				Line:     l.Line,
				Col:      l.Column,
			})
		}
	})

	return findings
}
