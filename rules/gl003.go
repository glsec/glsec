// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl003 struct{}

var GL003 = &gl003{}

func (r *gl003) ID() string { return "GL003" }

// shaPattern matches a full or short commit SHA (8–40 hex chars).
var shaPattern = regexp.MustCompile(`^[0-9a-f]{8,40}$`)

// integrityPattern matches an include:integrity value: a base64-encoded SHA256
// digest with its algorithm prefix.
var integrityPattern = regexp.MustCompile(`^sha256-[A-Za-z0-9+/]{43}=$`)

// mutableRefs are branch names that are clearly mutable version pointers.
var mutableRefs = map[string]bool{
	"main": true, "master": true, "dev": true, "develop": true,
	"staging": true, "production": true, "latest": true, "HEAD": true,
	"nightly": true, "canary": true, "edge": true,
	"stable": true, "trunk": true,
}

func (r *gl003) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	var findings []finding.Finding
	for _, item := range parser.IncludeItems(parser.FindKey(mapping, "include")) {
		findings = append(findings, checkIncludeItem(item, file)...)
	}
	return findings
}

func checkIncludeItem(node *yaml.Node, file string) []finding.Finding {
	if parser.FindKey(node, "local") != nil || parser.FindKey(node, "template") != nil {
		return nil
	}

	if remote := parser.FindKey(node, "remote"); remote != nil {
		// GitLab refuses the include when the fetched content does not match
		// the hash, so integrity: pins the content.
		if integrity := parser.FindKey(node, "integrity"); integrity != nil && integrityPattern.MatchString(integrity.Value) {
			return nil
		}
		if commitPinnedRawURL(remote.Value) {
			return nil
		}
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("remote include %q — URL content is mutable and unverified; pin it with integrity: sha256-<base64 hash> or use a project include with a pinned ref", remote.Value),
			File:     file,
			Line:     remote.Line,
			Col:      remote.Column,
		}}
	}

	if component := parser.FindKey(node, "component"); component != nil {
		return checkComponentRef(component, file)
	}

	if project := parser.FindKey(node, "project"); project != nil {
		return checkProjectRef(node, project, file)
	}

	return nil
}

func checkProjectRef(node *yaml.Node, projectNode *yaml.Node, file string) []finding.Finding {
	refNode := parser.FindKey(node, "ref")
	if refNode == nil {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("project include %q missing \"ref\" — defaults to HEAD of default branch (mutable)", projectNode.Value),
			File:     file,
			Line:     projectNode.Line,
			Col:      projectNode.Column,
		}}
	}
	if isMutableRef(refNode.Value) {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("project include %q uses mutable ref %q — pin to a commit SHA or tag", projectNode.Value, refNode.Value),
			File:     file,
			Line:     refNode.Line,
			Col:      refNode.Column,
		}}
	}
	return nil
}

func checkComponentRef(node *yaml.Node, file string) []finding.Finding {
	// component refs follow the format: "gitlab.com/org/component@ref"
	at := strings.LastIndex(node.Value, "@")
	if at < 0 {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("component include %q missing version — add @<tag-or-sha>", node.Value),
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		}}
	}
	ref := node.Value[at+1:]
	if ref == "~latest" || isMutableRef(ref) {
		return []finding.Finding{{
			RuleID:   "GL003",
			Severity: finding.Error,
			Message:  fmt.Sprintf("component include %q uses mutable ref %q — pin to a tag or commit SHA", node.Value, ref),
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		}}
	}
	return nil
}

// isMutableRef returns true if the ref is a known mutable branch name.
// SHA-like strings are considered pinned; everything else (tags) is allowed.
func isMutableRef(ref string) bool {
	if shaPattern.MatchString(ref) {
		return false
	}
	return mutableRefs[ref]
}

// IsMutableRef reports whether ref is a well-known branch name that moves,
// as GL003 judges include refs. The pipeline inventory uses it (#830).
func IsMutableRef(ref string) bool { return isMutableRef(ref) }

// fullCommitRe matches a full 40-character commit SHA.
var fullCommitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// commitPinnedRawURL reports a raw-file URL that names a full commit SHA on a
// Git host that serves files by commit, so its content cannot change, as with
// a project include pinned to a SHA (#1050):
//
//	https://raw.githubusercontent.com/<owner>/<repo>/<sha>/<path>
//	https://github.com/<owner>/<repo>/raw/<sha>/<path>
//	https://<gitlab>/<group>/<project>/-/raw/<sha>/<path>
//	https://bitbucket.org/<owner>/<repo>/raw/<sha>/<path>
//	https://<gitea>/<owner>/<repo>/raw/commit/<sha>/<path>
//	https://<gitlab>/api/v4/projects/<id>/repository/files/<path>/raw?ref=<sha>
func commitPinnedRawURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" {
		return false
	}
	seg := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if strings.HasPrefix(u.EscapedPath(), "/api/v4/projects/") && seg[len(seg)-1] == "raw" {
		return fullCommitRe.MatchString(u.Query().Get("ref"))
	}
	if u.Host == "raw.githubusercontent.com" {
		return len(seg) > 3 && fullCommitRe.MatchString(seg[2])
	}
	for i := 2; i < len(seg); i++ {
		if seg[i] != "raw" {
			continue
		}
		at := i + 1
		if at < len(seg) && seg[at] == "commit" {
			at++
		}
		if at+1 < len(seg) && fullCommitRe.MatchString(seg[at]) {
			return true
		}
	}
	return false
}
