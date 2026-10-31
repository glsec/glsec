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

type gl024 struct{}

var GL024 = &gl024{}

func (r *gl024) ID() string { return "GL024" }

var (
	// pipefailRe matches a line that enables pipefail.
	pipefailRe = regexp.MustCompile(`\bpipefail\b`)
)

// gl024Line is the result for one script line: how many pipelines a new
// shell runs without pipefail, where the first starts, and the command that
// starts that shell.
type gl024Line struct {
	count, first int
	via          string
}

// GitLab Runner starts bash and sh job scripts with set -o pipefail when the
// shell supports it (shells/bash.go in gitlab-runner, since 12.0 at least), so
// a pipe in script: already fails the job (#1047). What remains is a pipe in
// a script a new shell runs (sh -c, ssh), which starts without the option.
func (r *gl024) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	inherit := NewInheritance(doc)
	memo := nodeMemo[gl024Line]{}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// Windows runners run PowerShell, which has no pipefail (#615).
		if inherit.RunsOnWindows(job) {
			return
		}
		var first *yaml.Node
		var firstLine gl024Line
		count := 0
		for _, l := range CollectJobScriptLines(job) {
			res := memo.get(l, func() gl024Line { return gl024Scan(l.Value) })
			if res.count > 0 && first == nil {
				first, firstLine = l, res
			}
			count += res.count
		}
		if count == 0 {
			return
		}
		countHint := ""
		if count > 1 {
			countHint = fmt.Sprintf(" (%d piped lines in this job, first shown)", count)
		}
		f := finding.Finding{
			RuleID:   "GL024",
			Severity: finding.Info,
			Job:      name.Value,
			Message:  "pipe in a script run by `" + firstLine.via + "`" + countHint + " — the new shell starts without the runner's pipefail, so failures in all but the last command are ignored; add set -o pipefail to that script",
			File:     file,
			Line:     parser.ScalarContentLine(first, firstLine.first),
		}
		if firstLine.first == 0 {
			f.Col = first.Column
		}
		findings = append(findings, f) // one finding per job
	})

	return findings
}

// gl024Scan counts the commands of a script line that hand a new shell a
// script with a pipeline needing pipefail.
func gl024Scan(script string) gl024Line {
	var res gl024Line
	// Every shell name and ssh contain "sh".
	if !strings.Contains(script, "sh") {
		return res
	}
	for _, cmd := range shellCommands(maskCasePatterns(script)) {
		if !strings.Contains(cmd.text, "sh") {
			continue
		}
		via, inner, errexit, ok := childShellScript(withoutSudo(commandWords(cmd.text)))
		if !ok || pipefailRe.MatchString(inner) || !needsPipefail(inner, errexit || errexitRe.MatchString(inner)) {
			continue
		}
		if res.count == 0 {
			res.first, res.via = cmd.line, via
		}
		res.count++
	}
	return res
}

// errexitRe matches set -e, also bundled (set -eu) or spelled set -o errexit.
var errexitRe = regexp.MustCompile(`\bset\s+(?:-[a-zA-Z]*e[a-zA-Z]*\b|-o\s+errexit\b)`)

// needsPipefail reports whether a script has a pipeline whose status counts
// and whose earlier commands can fail unnoticed. Without errexit, the status
// of a pipeline counts only when it is the script's last command or && tests
// it. Skipped are pipelines whose commands before the last only print (echo
// "$X" | docker login --password-stdin), pipelines tested as a condition
// (if/while/until a | grep -q x), those whose failure is handled with ||, and
// those inside a command substitution, whose status is lost.
func needsPipefail(script string, errexit bool) bool {
	cmds := shellCommands(maskCasePatterns(script))
	for i := 0; i < len(cmds); {
		j := i
		for j < len(cmds)-1 && cmds[j].piped {
			j++
		}
		pipeline := cmds[i : j+1]
		i = j + 1
		last := pipeline[len(pipeline)-1]
		switch {
		case len(pipeline) < 2, last.orElse, isCondition(pipeline[0].text), isQuietGrep(last.text),
			opensSubstitution(pipeline[0].text),
			!errexit && i < len(cmds) && !last.andThen:
			continue
		}
		for _, c := range pipeline[:len(pipeline)-1] {
			if !isSimplePrintCommand(c.text) {
				return true
			}
		}
	}
	return false
}

// opensSubstitution reports whether text leaves a $( or backtick open: the
// pipeline it starts runs inside a command substitution.
func opensSubstitution(text string) bool {
	depth, backtick := 0, false
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			i++
		case c == '\'' && quote == 0:
			quote = c
		case c == '"':
			if quote == '"' {
				quote = 0
			} else {
				quote = c
			}
		case c == '$' && i+1 < len(text) && text[i+1] == '(':
			depth++
			i++
		case c == ')' && depth > 0 && quote == 0:
			depth--
		case c == '`':
			backtick = !backtick
		}
	}
	return depth > 0 || backtick
}

// isCondition reports a command that starts the condition of if, elif, while
// or until, or is negated with !.
func isCondition(text string) bool {
	f := strings.Fields(text)
	if len(f) == 0 {
		return false
	}
	switch f[0] {
	case "if", "elif", "while", "until", "!":
		return true
	}
	return false
}

// isQuietGrep reports a grep that only tests for a match: grep -q, or its
// output sent to /dev/null.
func isQuietGrep(text string) bool {
	words := commandWords(text)
	if commandName(words) != "grep" {
		return false
	}
	if strings.Contains(text, "/dev/null") {
		return true
	}
	for _, w := range words[1:] {
		if w == "--quiet" || w == "--silent" || len(w) > 1 && w[0] == '-' && w[1] != '-' && strings.ContainsRune(w, 'q') {
			return true
		}
	}
	return false
}

// childShells start a new shell for the script after -c.
var childShells = map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true}

// sshValueOptions are the ssh options that take a value.
const sshValueOptions = "BbcDEeFIiJLlmOoPpQRSWw"

// childShellScript returns the script a command hands to a new shell: the
// argument after sh -c (also bundled, as in -ec, and wrapped, as in docker run
// img sh -c …) or the remote command of ssh, and whether the shell is
// started with -e. A shell started with -o pipefail is skipped.
func childShellScript(words []string) (via, script string, errexit, ok bool) {
	if len(words) == 0 || words[0] == "echo" || words[0] == "printf" {
		return "", "", false, false
	}
	if commandName(words) == "ssh" {
		i := 1
		for ; i < len(words) && len(words[i]) > 1 && words[i][0] == '-'; i++ {
			if len(words[i]) == 2 && strings.IndexByte(sshValueOptions, words[i][1]) >= 0 {
				i++
			}
		}
		if i+1 < len(words) {
			return "ssh", strings.Join(words[i+1:], " "), false, true
		}
		return "", "", false, false
	}
	for i, w := range words {
		name := commandName([]string{w})
		if !childShells[name] {
			continue
		}
		for j := i + 1; j < len(words) && strings.HasPrefix(words[j], "-") && !strings.HasPrefix(words[j], "--"); j++ {
			if words[j] == "-o" && j+1 < len(words) && words[j+1] == "pipefail" {
				return "", "", false, false
			}
			if strings.ContainsRune(words[j][1:], 'e') {
				errexit = true
			}
			if strings.ContainsRune(words[j][1:], 'c') {
				if j+1 < len(words) {
					return name + " " + words[j], words[j+1], errexit, true
				}
				return "", "", false, false
			}
		}
	}
	return "", "", false, false
}

// isSimplePrintCommand recognises commands that only write an existing value.
func isSimplePrintCommand(text string) bool {
	// A pipeline inside a command substitution starts after its $( or
	// backtick: X=$(echo … | cut …), echo "$(echo … | cut …)", [ "$(…)" ]
	// (#983).
	if i := lastSubstitutionStart(text); i >= 0 {
		text = text[i:]
	}
	words := commandWords(text)
	if len(words) == 0 || words[0] != "echo" && words[0] != "printf" {
		return false
	}
	// Keep checking substitutions, compound commands and redirections: they
	// can do more than print. Quoted or escaped syntax is only argument data.
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\\' && quote != '\'':
			i++
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\'' && quote == 0:
			quote = c
		case c == '"':
			if quote == '"' {
				quote = 0
			} else {
				quote = c
			}
		case c == '`' || c == '$' && strings.HasPrefix(text[i:], "$("):
			return false
		case quote == 0 && strings.ContainsRune("()<>", rune(c)):
			return false
		}
	}
	return true
}

// maskCasePatterns blanks the | between the patterns of a case arm
// (`main | release-* )`), which separates alternatives, not commands (#983).
func maskCasePatterns(script string) string {
	if !strings.Contains(script, "case") {
		return script
	}
	b := []byte(script)
	const (
		outside = iota
		header  // after case, until in
		pattern // before the ) of an arm
		body    // the arm's commands, until ;; or esac
	)
	mode := outside
	var quote byte
	word := func(i int, w string) bool {
		if !strings.HasPrefix(script[i:], w) || i > 0 && !isWordBoundary(script[i-1]) {
			return false
		}
		end := i + len(w)
		return end == len(script) || isWordBoundary(script[end])
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case mode == outside && word(i, "case"):
			mode = header
		case mode == header && word(i, "in"):
			mode = pattern
		case mode == pattern && word(i, "esac"):
			mode = outside
		case mode == pattern && c == '|':
			b[i] = ' '
		case mode == pattern && c == ')':
			mode = body
		case mode == body && c == ';' && i+1 < len(b) && (b[i+1] == ';' || b[i+1] == '&'):
			mode = pattern
			i++
		case mode == body && word(i, "esac"):
			mode = outside
		}
	}
	return string(b)
}

func isWordBoundary(c byte) bool {
	return isShellSpace(c) || c == '\n' || c == ';' || c == '(' || c == ')'
}

// lastSubstitutionStart returns the index after the last $( or backtick of
// text that isn't inside single quotes, or -1.
func lastSubstitutionStart(text string) int {
	last := -1
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			i++
		case c == '\'':
			quote = c
		case c == '$' && i+1 < len(text) && text[i+1] == '(':
			last = i + 2
			i++
		case c == '`':
			last = i + 1
		}
	}
	return last
}
