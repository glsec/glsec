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

type gl062 struct{}

var GL062 = &gl062{}

func (r *gl062) ID() string { return "GL062" }

// envFullDumpRe matches a standalone `printenv` or `env` command (optionally
// path-prefixed) with no arguments — i.e. one that dumps the entire
// environment. The command must sit at a shell command boundary and be
// followed immediately by end-of-line or a shell separator, so
// `printenv VAR` and `env VAR=v cmd` are not matched.
// (?m): in a multi-line block the command can be on any line (#975).
var envFullDumpRe = regexp.MustCompile(`(?m)(?:^|[;&|(])\s*(?:/usr/bin/|/bin/)?(?:printenv|env)\s*(?:$|[;&|#)])`)

func (r *gl062) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !envFullDumpRe.MatchString(v) {
			return
		}
		for _, cmd := range shellCommands(v) {
			loc := envFullDumpRe.FindStringIndex(cmd.text)
			// Output captured by $(…) or backticks goes to a variable or an
			// argument, not to the log: X=$(env | grep …), for v in $(env …).
			if loc == nil || strings.Contains(cmd.text[:loc[1]], "$(") || strings.Contains(cmd.text[:loc[1]], "`") {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL062",
				Severity: finding.Warn,
				Job:      job,
				Message:  "printenv/env with no arguments dumps every environment variable to the job log, including CI/CD secrets and tokens that may not be reliably masked — print only the specific variables you need",
				File:     file,
				Line:     parser.ScalarContentLine(line, cmd.line),
			}
			if cmd.line == 0 {
				f.Col = line.Column
			}
			findings = append(findings, f)
			return
		}
	})
	return findings
}
