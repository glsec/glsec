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
			words := commandWords(cmd.text)
			if commandName(words) != "sudo" && !sudoSubstRe.MatchString(maskSingleQuoted(cmd.text)) {
				continue
			}
			if commandName(words) == "sudo" && sudoDropsPrivileges(words[1:]) {
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

// sudoDropsPrivileges reports whether sudo's options run the command as a
// user other than root (-u nobody, --user=builder): that runs it with fewer
// privileges, not more (#994).
func sudoDropsPrivileges(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		user := ""
		switch {
		case a == "-u" || a == "--user":
			if i+1 < len(args) {
				user = args[i+1]
			}
		case strings.HasPrefix(a, "--user="):
			user = strings.TrimPrefix(a, "--user=")
		case strings.HasPrefix(a, "-u") && len(a) > 2:
			user = a[2:]
		case strings.HasPrefix(a, "-") && strings.HasSuffix(a, "u") && !strings.HasPrefix(a, "--"):
			// a cluster such as -Eu user or -Hu user
			if i+1 < len(args) {
				user = args[i+1]
			}
		case !strings.HasPrefix(a, "-"):
			return false // the command starts here
		}
		if user != "" {
			return user != "root" && user != "0" && user != "#0"
		}
	}
	return false
}
