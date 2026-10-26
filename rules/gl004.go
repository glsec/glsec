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
	jobTokenPattern = regexp.MustCompile(`\$\{?CI_JOB_TOKEN\}?`)
)

func (r *gl004) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		for _, f := range scanScriptForToken(node, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})
	return findings
}

func scanScriptForToken(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			findings = append(findings, checkTokenLine(item, file)...)
		}
	}
	return findings
}

// checkTokenLine reports a command that passes $CI_JOB_TOKEN and names a
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
			f := finding.Finding{
				RuleID:   "GL004",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"CI_JOB_TOKEN sent to non-GitLab host %q — this token is scoped to the GitLab API and should not be forwarded to external services",
					host,
				),
				File: file,
				Line: parser.ScalarContentLine(node, cmd.line),
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

func isGitLabDomain(domain string) bool {
	return domain == "gitlab.com" || strings.HasSuffix(domain, ".gitlab.com")
}
