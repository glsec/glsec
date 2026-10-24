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

// urlEncodedArgRe matches a --data-urlencode argument. curl percent-encodes
// its value, so a variable there can't change the host, path or other fields.
var urlEncodedArgRe = regexp.MustCompile(`--data-urlencode(?:=|\s+)(?:"[^"]*"|'[^']*'|\S+)`)

func (r *gl025) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, l := range CollectJobScriptLines(job) {
			m := userVarInRequest(l.Value)
			if m == "" {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL025",
				Severity: finding.Warn,
				Job:      name.Value,
				Message:  "curl/wget request includes user-controlled variable " + m + " — whoever names the branch or writes the commit or merge request controls part of the URL or request body",
				File:     file,
				Line:     l.Line,
				Col:      l.Column,
			})
		}
	})

	return findings
}

// shellAssignRe matches a shell variable assignment at the start of a line, with
// an optional export. Group 1 is the name, group 2 the value.
var shellAssignRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// sanitiserRe matches the usual ways to strip or encode a value before it goes
// into a URL: deleting all but a safe character set, sed, or jq's @uri.
var sanitiserRe = regexp.MustCompile(`\btr\s+-(?:cd|dc)\b|\bsed\b|@uri\b`)

// userVarInRequest returns the first user-controlled variable used in a curl
// or wget command in script, or "". Each shell line is checked on its own
// (with \ continuations joined). A variable assigned from a user-controlled
// one on an earlier line counts as that variable unless the assignment
// sanitises it.
func userVarInRequest(script string) string {
	tainted := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(script, "\\\n", " "), "\n") {
		if a := shellAssignRe.FindStringSubmatch(line); a != nil {
			if m := userControlledVarRe.FindString(a[2]); m != "" && !sanitiserRe.MatchString(a[2]) {
				tainted[a[1]] = m
			} else if src := taintedRef(a[2], tainted); src != "" {
				tainted[a[1]] = src
			} else {
				delete(tainted, a[1])
			}
		}
		if !curlWgetRe.MatchString(line) {
			continue
		}
		request := urlEncodedArgRe.ReplaceAllString(line, "")
		if m := userControlledVarRe.FindString(request); m != "" {
			return m
		}
		if src := taintedRef(request, tainted); src != "" {
			return src
		}
	}
	return ""
}

// shellVarRefRe matches a shell variable reference; group 1 is the name.
var shellVarRefRe = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)

// taintedRef returns the user-controlled variable behind the first reference
// in s to a tainted shell variable, or "".
func taintedRef(s string, tainted map[string]string) string {
	for _, m := range shellVarRefRe.FindAllStringSubmatch(s, -1) {
		if src, ok := tainted[m[1]]; ok {
			return src
		}
	}
	return ""
}
