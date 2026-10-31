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

type gl004 struct{}

var GL004 = &gl004{}

func (r *gl004) ID() string { return "GL004" }

var (
	// jobTokenPattern matches a CI_JOB_TOKEN reference in POSIX shell
	// form ($CI_JOB_TOKEN, ${CI_JOB_TOKEN}, case sensitive) and in
	// PowerShell form ($env:CI_JOB_TOKEN, ${env:CI_JOB_TOKEN}), where
	// variable names are case insensitive, so the env: prefix and the
	// token name match in any case. A lowercase POSIX reference
	// ($ci_job_token) is a different variable and does not match.
	jobTokenPattern = regexp.MustCompile(`\$\{?CI_JOB_TOKEN\}?|\$(?i:\{?env:CI_JOB_TOKEN\}?)`)
)

func (r *gl004) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		for _, f := range checkTokenLine(line, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})
	return findings
}

// checkTokenLine reports a command that passes $CI_JOB_TOKEN (or its
// PowerShell form $env:CI_JOB_TOKEN) and names a
// non-GitLab host as a URL argument. Each command of a block is looked at on
// its own, and only words that are URLs count: a URL in an echo, a form value
// (-F "x=https://…") or another command of the block is not where the token
// goes.
func checkTokenLine(node *yaml.Node, file string) []finding.Finding {
	if !jobTokenPattern.MatchString(node.Value) {
		return nil
	}
	var findings []finding.Finding
	for _, cmd := range shellCommands(node.Value) {
		if !jobTokenPattern.MatchString(cmd.text) {
			continue
		}
		for _, w := range shellWords(cmd.text) {
			host := urlHost(w)
			if host == "" || isGitLabDomain(host) {
				continue
			}
			msg := fmt.Sprintf(
				"CI_JOB_TOKEN sent to non-GitLab host %q — this token is scoped to the GitLab API and should not be forwarded to external services",
				host,
			)
			if hasGitLabShape(w) {
				msg = fmt.Sprintf(
					"CI_JOB_TOKEN sent to hardcoded GitLab host %q — if this is the instance running the pipeline, use $CI_API_V4_URL / $CI_SERVER_HOST so the token can't go to another instance after a move or fork",
					host,
				)
			}
			f := finding.Finding{
				RuleID:   "GL004",
				Severity: finding.Warn,
				Message:  msg,
				File:     file,
				Line:     parser.ScalarContentLine(node, cmd.line),
			}
			if cmd.line == 0 {
				f.Col = node.Column
			}
			findings = append(findings, f)
			break
		}
	}
	return findings
}

// urlHost returns the host of a word that is an http(s) URL, without userinfo
// and port. A host given by a variable ($CI_SERVER_HOST) is unknown and
// returns "".
func urlHost(word string) string {
	if strings.HasPrefix(word, "-") {
		if i := strings.IndexByte(word, '='); i >= 0 {
			word = word[i+1:] // --url=https://…
		}
	}
	m := urlWordRe.FindStringSubmatch(word)
	if m == nil {
		return ""
	}
	rest := m[1]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	if !hostRe.MatchString(rest) {
		return ""
	}
	return strings.ToLower(rest)
}

var (
	urlWordRe = regexp.MustCompile(`^(?i:https?)://(.+)$`)
	hostRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-]*$`)
)

// gitLabShapes are the markers of a GitLab API, job-artifact or trigger URL.
// The gitlab-ci-token userinfo is not one: every job-token clone uses it,
// also of a repository on GitHub, so it says nothing about the host.
var gitLabShapes = []string{"/api/v4/", "/-/jobs/artifacts/", "/trigger/pipeline"}

// hasGitLabShape reports whether a URL word has the shape of a GitLab
// instance's URL, which suggests a self-hosted instance rather than an
// unrelated service.
func hasGitLabShape(word string) bool {
	word = strings.ToLower(word)
	for _, s := range gitLabShapes {
		if strings.Contains(word, s) {
			return true
		}
	}
	return false
}

func isGitLabDomain(domain string) bool {
	return domain == "gitlab.com" || strings.HasSuffix(domain, ".gitlab.com")
}
