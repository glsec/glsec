// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"path"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// pagesJob reports whether a job deploys GitLab Pages: it is named pages or
// has a pages: key that isn't false (parallel deployments included).
func pagesJob(name string, job *yaml.Node) bool {
	p := parser.FindKey(job, "pages")
	if p == nil {
		return name == "pages"
	}
	return p.Kind != yaml.ScalarNode || !parser.IsFalse(p)
}

// pagesPublish returns a Pages job's content directory node: pages:publish,
// else the deprecated top-level publish:. nil means GitLab's default, public.
func pagesPublish(job *yaml.Node) *yaml.Node {
	if p := parser.FindKey(job, "pages"); p != nil && p.Kind == yaml.MappingNode {
		if v := parser.FindKey(p, "publish"); v != nil {
			return v
		}
	}
	return parser.FindKey(job, "publish")
}

// checkPagesPublish reports a Pages job whose published directory is the
// whole working directory or holds .git (#1499). Since GitLab 17.10 the
// publish path is appended to artifacts:paths, and Pages serves every file in
// it, dotfiles and .git included. An artifacts:paths entry that already
// uploads the whole directory is reported by checkArtifactPath instead.
func checkPagesPublish(name string, job *yaml.Node, file string) []finding.Finding {
	if !pagesJob(name, job) {
		return nil
	}
	var findings []finding.Finding
	pub := pagesPublish(job)
	lines := CollectJobScriptLines(job)
	if pub != nil && pub.Kind == yaml.ScalarNode && pub.ShortTag() != "!!null" {
		var msg string
		switch {
		case isWholeProjectArtifactPath(pub.Value) && !uploadsWholeDir(job) && !removesGitFrom(lines, pub.Value):
			msg = fmt.Sprintf("Pages publish path %q is the whole working directory — GitLab Pages serves it as the site, with .git (history and Git configuration), the CI configuration and every file the job generated; publish a build directory such as public", pub.Value)
		case strings.Contains("/"+strings.TrimPrefix(pub.Value, "./")+"/", "/.git/"):
			msg = fmt.Sprintf("Pages publish path %q includes a .git directory — GitLab Pages serves the repository history and Git configuration", pub.Value)
		}
		if msg != "" {
			findings = append(findings, finding.Finding{
				RuleID: "GL005", Severity: finding.Error, Job: name, Message: msg,
				File: file, Line: pub.Line, Col: pub.Column,
			})
		}
	}
	dir := "public"
	if pub != nil && pub.Kind == yaml.ScalarNode && pub.ShortTag() != "!!null" {
		dir = pub.Value
	}
	if removesGitFrom(lines, dir) {
		return findings
	}
	for _, line := range lines {
		if !strings.Contains(line.Value, "cp") && !strings.Contains(line.Value, "rsync") {
			continue
		}
		for _, cmd := range shellCommands(line.Value) {
			if !copiesProjectInto(cmd.text, line.Value, dir) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL005",
				Severity: finding.Error,
				Job:      name,
				Message:  fmt.Sprintf("Pages job copies the whole project directory into %q without excluding .git — GitLab Pages serves .git/config, the repository history and every file the job created; copy only the site files, or exclude .git (rsync --exclude=.git)", dir),
				File:     file,
				Line:     parser.ScalarContentLine(line, cmd.line),
				Col:      line.Column,
			})
		}
	}
	return findings
}

// uploadsWholeDir reports an artifacts:paths entry of the job itself that
// uploads the whole working directory.
func uploadsWholeDir(job *yaml.Node) bool {
	artifacts := parser.FindKey(job, "artifacts")
	if artifacts == nil || artifacts.Kind != yaml.MappingNode {
		return false
	}
	paths := parser.FindKey(artifacts, "paths")
	if paths == nil || paths.Kind != yaml.SequenceNode {
		return false
	}
	for _, p := range paths.Content {
		if p.Kind == yaml.ScalarNode && isWholeProjectArtifactPath(p.Value) {
			return true
		}
	}
	return false
}

// copiesProjectInto reports a recursive cp or rsync of the project directory
// (., ./, $CI_PROJECT_DIR) into dir that doesn't exclude .git. A cp that copies
// a directory into itself fails, so it only counts when the line goes on
// after a failure (|| true); rsync skips an excluded public/ and succeeds.
func copiesProjectInto(text, line, dir string) bool {
	words := commandWords(text)
	name := commandName(words)
	if name != "cp" && name != "rsync" {
		return false
	}
	recursive, excludesGit, fromProject := false, false, false
	var args []string
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "--recursive" || w == "--archive":
			recursive = true
		case strings.HasPrefix(w, "--exclude"):
			v := strings.TrimPrefix(strings.TrimPrefix(w, "--exclude"), "=")
			if v == "" && i+1 < len(words) {
				i++
				v = words[i]
			}
			if excludesDotGit(strings.Trim(v, `"'`)) {
				excludesGit = true
			}
		case w == "-C" || w == "--cvs-exclude" || w == "-F" || strings.HasPrefix(w, "--filter") || strings.HasPrefix(w, "--exclude-from"):
			excludesGit = true // rsync's CVS rules and filter files; unknown, so not reported
		case strings.HasPrefix(w, "--"):
		case strings.HasPrefix(w, "-") && len(w) > 1:
			if strings.ContainsAny(w[1:], "rRa") {
				recursive = true
			}
		default:
			args = append(args, w)
		}
	}
	if !recursive || excludesGit || len(args) < 2 {
		return false
	}
	for _, src := range args[:len(args)-1] {
		switch strings.TrimSuffix(strings.TrimSuffix(src, "/."), "/") {
		case ".", "", "$CI_PROJECT_DIR", "${CI_PROJECT_DIR}":
			fromProject = true
		}
	}
	if !fromProject || cleanDir(args[len(args)-1]) != cleanDir(dir) {
		return false
	}
	return name == "rsync" || strings.Contains(line, "||")
}

func cleanDir(p string) string {
	p = strings.Trim(p, `"'`)
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	p = strings.TrimPrefix(p, "$CI_PROJECT_DIR/")
	p = strings.TrimPrefix(p, "${CI_PROJECT_DIR}/")
	return strings.TrimSuffix(p, "/")
}

// excludesDotGit reports an rsync --exclude pattern that matches .git, such as
// .git, .git/, /.git, .git*, .* or *.
func excludesDotGit(pattern string) bool {
	pattern = strings.TrimSuffix(strings.TrimPrefix(pattern, "/"), "/")
	ok, err := path.Match(pattern, ".git")
	return ok && err == nil
}

// removesGitFrom reports a script that deletes dir/.git, as in rm -rf
// public/.git, or .git itself when dir is the working directory.
func removesGitFrom(lines []*yaml.Node, dir string) bool {
	want := cleanDir(dir) + "/.git"
	if isWholeProjectArtifactPath(dir) {
		want = ".git"
	}
	for _, line := range lines {
		if !strings.Contains(line.Value, ".git") {
			continue
		}
		for _, cmd := range shellCommands(line.Value) {
			words := commandWords(cmd.text)
			if commandName(words) != "rm" {
				continue
			}
			for _, w := range words[1:] {
				if cleanDir(w) == want {
					return true
				}
			}
		}
	}
	return false
}
