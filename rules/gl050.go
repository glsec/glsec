// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl050 struct{}

var GL050 = &gl050{}

func (r *gl050) ID() string { return "GL050" }

// sudoSubstRe matches sudo run inside a command substitution: test $(sudo …).
var sudoSubstRe = regexp.MustCompile("(?:\\$\\(|`)\\s*sudo\\b")

func (r *gl050) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		// Only sudo as the command a line runs counts: not the sudo package in
		// an install list, and not the word in text a heredoc writes.
		for _, cmd := range shellCommands(line.Value) {
			if commandName(commandWords(cmd.text)) != "sudo" && !sudoSubstRe.MatchString(maskSingleQuoted(cmd.text)) {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL050",
				Severity: finding.Warn,
				Job:      job,
				Message:  "sudo in CI script escalates privileges — use a container image with required tools pre-installed instead",
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
