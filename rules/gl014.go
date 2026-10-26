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

type gl014 struct{}

var GL014 = &gl014{}

func (r *gl014) ID() string { return "GL014" }

// envDumpRe matches a command that writes the whole environment to a file:
// env, printenv, export -p or cat /proc/self/environ, redirected with > or >>
// or piped into tee. The command has to start a command, so "cat .env > f"
// and "printenv VAR > f" (a single variable) don't match. Group 1 or 2 is the
// target file.
var envDumpRe = regexp.MustCompile(
	`(?:^|[\s;&|(])(?:env|printenv|export\s+-p|cat\s+/proc/(?:self|\$\$|[0-9]+)/environ)\s*` +
		`(?:>>?\s*(\S+)|\|\s*tee\s+(?:(?:-a|--append)\s+)?(\S+))`)

// projectDirPrefixRe matches a target written relative to the project
// directory through its variable.
var projectDirPrefixRe = regexp.MustCompile(`^\$\{?CI_PROJECT_DIR\}?/`)

func (r *gl014) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	def := parser.FindKey(parser.Unwrap(doc), "default")

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		artifacts := parser.FindKey(job, "artifacts")
		if artifacts == nil && def != nil {
			artifacts = parser.FindKey(def, "artifacts")
		}
		if artifacts == nil || artifacts.Kind != yaml.MappingNode {
			return
		}
		dotenv := dotenvArtifactNode(artifacts)
		eachJobScriptLine(job, func(item *yaml.Node) bool {
			for _, m := range envDumpRe.FindAllStringSubmatch(item.Value, -1) {
				target := m[1] + m[2]
				var msg string
				switch {
				case dotenv != nil:
					msg = fmt.Sprintf("job %q dumps all environment variables to a dotenv artifact — CI_JOB_TOKEN and masked secrets are included and downloadable by any pipeline viewer", name.Value)
				case artifactCovers(artifacts, target):
					msg = fmt.Sprintf("job %q dumps all environment variables to %q, which its artifacts upload — CI_JOB_TOKEN and masked secrets are included and downloadable by anyone who can read the artifacts", name.Value, target)
				default:
					continue
				}
				findings = append(findings, finding.Finding{
					RuleID:   "GL014",
					Severity: finding.Warn,
					Job:      name.Value,
					Message:  msg,
					File:     file,
					Line:     item.Line,
					Col:      item.Column,
				})
				return false // one finding per job is enough
			}
			return true
		})
	})

	return findings
}

// eachJobScriptLine calls fn for every scalar script line of a job until fn
// returns false.
func eachJobScriptLine(job *yaml.Node, fn func(item *yaml.Node) bool) {
	blocks := []*yaml.Node{
		parser.FindKey(job, "script"),
		parser.FindKey(job, "before_script"),
		parser.FindKey(job, "after_script"),
		hookScriptNode(job),
	}
	blocks = append(blocks, parser.RunStepBlocks(job)...)
	for _, block := range blocks {
		if block == nil || block.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range block.Content {
			if item.Kind == yaml.ScalarNode && !fn(item) {
				return
			}
		}
	}
}

// dotenvArtifactNode returns the dotenv value node if the artifacts block sets
// reports:dotenv, otherwise nil.
func dotenvArtifactNode(artifacts *yaml.Node) *yaml.Node {
	reports := parser.FindKey(artifacts, "reports")
	if reports == nil {
		return nil
	}
	return parser.FindKey(reports, "dotenv")
}

// artifactCovers reports whether an artifacts block uploads target, a file
// written by the job: untracked: true takes every file the job created, and
// paths: entries are globs relative to the project directory where ** spans
// directories and a directory takes everything below it. exclude: entries
// remove matching files again. A target outside the project directory or
// given by a variable is never matched against paths:.
func artifactCovers(artifacts *yaml.Node, target string) bool {
	target = projectDirPrefixRe.ReplaceAllString(strings.Trim(target, `"'`), "")
	target = strings.TrimPrefix(target, "./")
	known := target != "" && !strings.HasPrefix(target, "/") && !strings.Contains(target, "$") && !strings.Contains(target, "..")
	if known && artifactGlobsMatch(parser.FindKey(artifacts, "exclude"), target) {
		return false
	}
	if u := parser.FindKey(artifacts, "untracked"); u != nil && u.Value == "true" {
		return true
	}
	return known && artifactGlobsMatch(parser.FindKey(artifacts, "paths"), target)
}

// artifactGlobsMatch reports whether any glob in a paths: or exclude: list
// matches target or one of its parent directories.
func artifactGlobsMatch(list *yaml.Node, target string) bool {
	if list == nil || list.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range list.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		pattern := strings.TrimSuffix(strings.TrimPrefix(item.Value, "./"), "/")
		if pattern == "" || pattern == "." {
			return true
		}
		re := artifactGlobRe(pattern)
		for p := target; ; {
			if re.MatchString(p) {
				return true
			}
			i := strings.LastIndexByte(p, '/')
			if i < 0 {
				break
			}
			p = p[:i]
		}
	}
	return false
}

// artifactGlobRe translates an artifact glob to a regexp: ** matches across
// directories, * and ? within one path segment.
func artifactGlobRe(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i++
		case pattern[i] == '*':
			b.WriteString("[^/]*")
		case pattern[i] == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
