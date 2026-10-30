// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"unicode"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl068 struct{}

var GL068 = &gl068{}

func (r *gl068) ID() string { return "GL068" }

const xtraceLeakTail = " — every command is printed to the job log after variable expansion, so any command referencing a secret (token in a git URL, Authorization header, --key flag) leaks it in plaintext"

const xtraceSetMessage = "set -x enables shell xtrace" + xtraceLeakTail + "; drop the x (use set -euo pipefail) or scope tracing with set +x around secret-touching commands"

func (r *gl068) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		if strings.HasPrefix(strings.TrimSpace(line.Value), "#") {
			return
		}
		msg, at, ok := scriptLineXtraceMessage(line.Value)
		if !ok {
			return
		}
		ln, col := scriptLinePos(line, at)
		findings = append(findings, finding.Finding{
			RuleID:   "GL068",
			Severity: finding.Warn,
			Job:      job,
			Message:  msg,
			File:     file,
			Line:     ln,
			Col:      col,
		})
	})
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		if vars == nil || vars.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(vars.Content); i += 2 {
			if vars.Content[i].Value != "SHELLOPTS" {
				continue
			}
			scalar := resolveScalar(vars.Content[i+1])
			if scalar == nil || !shellOptsValueHasXtrace(scalar.Value) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL068",
				Severity: finding.Warn,
				Job:      job,
				Message:  "SHELLOPTS containing xtrace enables shell xtrace" + xtraceLeakTail + "; remove xtrace from SHELLOPTS",
				File:     file,
				Line:     vars.Content[i].Line,
				Col:      vars.Content[i].Column,
			})
		}
	})
	return findings
}

// scriptLineXtraceMessage reports how a script item enables xtrace, if it
// does. The set form keeps its net-effect rule: a self-contained
// `set -x …; set +x` block on one item (the documented way to scope tracing
// to a non-secret section) is not flagged, while a bare `set -x` is. A shell
// invoked with tracing, or a SHELLOPTS assignment enabling xtrace, flags the
// item regardless of what follows it, since the traced shell or the exported
// option outlives the line.
// It also returns the index of the item line the enabling command is on.
func scriptLineXtraceMessage(item string) (string, int, bool) {
	enabled := false
	touched := false
	at := 0
	// A set -x inside a ( … ) subshell ends with it (#997).
	for _, cmd := range shellCommands(blankSubshells(item)) {
		if on, ok := setCommandXtrace(cmd.text); ok {
			enabled = on
			touched = true
			if on {
				at = cmd.line
			}
		}
	}
	if touched && enabled {
		return xtraceSetMessage, at, true
	}
	for _, cmd := range shellCommands(item) {
		if name, ok := shellInvocationXtrace(cmd.text); ok {
			return "invoking " + name + " with xtrace enabled" + xtraceLeakTail + "; drop the x from the invocation", cmd.line, true
		}
	}
	for _, cmd := range shellCommands(item) {
		if scriptShellOptsXtrace(cmd.text) {
			return "SHELLOPTS containing xtrace enables shell xtrace" + xtraceLeakTail + "; remove xtrace from SHELLOPTS", cmd.line, true
		}
	}
	return "", 0, false
}

// setCommandXtrace parses one simple command and reports whether it is a
// `set` command that changes the xtrace option and to what value. ok is false
// for any other command, so `echo set -x` or `unset` are not matched.
func setCommandXtrace(cmd string) (on, ok bool) {
	words := commandWords(cmd)
	if len(words) == 0 || words[0] != "set" {
		return false, false
	}
	return xtraceArg(strings.Join(words[1:], " "))
}

// xtraceArg parses a `set` argument list and reports whether it changes the
// xtrace option and to what value. It recognises clustered short flags
// (-x, -euxo), their disabling form (+x), and the long form (-o xtrace /
// +o xtrace). ok is false when the arguments do not touch xtrace at all.
func xtraceArg(args string) (on, ok bool) {
	tokens := strings.Fields(args)
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if (t == "-o" || t == "+o") && i+1 < len(tokens) && tokens[i+1] == "xtrace" {
			on, ok = t == "-o", true
			i++
			continue
		}
		if len(t) >= 2 && (t[0] == '-' || t[0] == '+') && isFlagCluster(t[1:]) && strings.ContainsRune(t, 'x') {
			on, ok = t[0] == '-', true
		}
	}
	return on, ok
}

// isFlagCluster reports whether s is a run of ASCII letters, i.e. a bundle of
// single-character shell options such as "euxo".
func isFlagCluster(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !unicode.IsLetter(c) {
			return false
		}
	}
	return true
}

// shellNames are the shells whose invocation flags turn on tracing for the
// commands they run.
var shellNames = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true,
}

// shellInvocationXtrace reports whether one simple command invokes a shell
// with tracing enabled, and the shell name. Only flags before the first
// non-option argument count: in `bash script.sh -x` the -x belongs to the
// script, not the shell, so it is not flagged. `-o xtrace` counts; `+o
// xtrace` (disabling) does not.
func shellInvocationXtrace(cmd string) (string, bool) {
	words := withoutSudo(commandWords(cmd))
	if len(words) == 0 {
		return "", false
	}
	name := commandName(words)
	if !shellNames[name] {
		return "", false
	}
	args := words[1:]
	for i := 0; i < len(args); i++ {
		t := args[i]
		switch {
		case t == "--":
			return "", false
		case t == "-o" && i+1 < len(args) && args[i+1] == "xtrace":
			return name, true
		case t == "+o" && i+1 < len(args) && args[i+1] == "xtrace":
			i++
		case len(t) >= 2 && t[0] == '-' && isFlagCluster(t[1:]) && strings.ContainsRune(t, 'x'):
			return name, true
		case strings.HasPrefix(t, "-"):
			// Any other flag (including -c, whose argument is the
			// command string) does not enable tracing; keep scanning
			// only while arguments are still flags.
			continue
		default:
			// First non-option argument: the script, or the -c
			// command string. Everything after it belongs to the
			// script, not the invoking shell.
			return "", false
		}
	}
	return "", false
}

// scriptShellOptsXtrace reports whether one simple command assigns xtrace to
// SHELLOPTS, as a leading assignment or through export/local/readonly/
// declare. Only leading assignments count, so `echo SHELLOPTS=xtrace` and
// arguments of other commands stay quiet.
func scriptShellOptsXtrace(cmd string) bool {
	words := shellWords(cmd)
	skipFlags := false
	for _, w := range words {
		switch {
		case w == "export" || w == "local" || w == "readonly" || w == "command" || w == "time" || w == "nohup":
			skipFlags = false
		case w == "declare" || w == "env" || w == "sudo":
			skipFlags = true
		case skipFlags && strings.HasPrefix(w, "-"):
			// A flag of declare/env/sudo, e.g. declare -x.
		case strings.HasPrefix(w, "SHELLOPTS=") || strings.HasPrefix(w, "SHELLOPTS+="):
			skipFlags = false
			value := w[strings.IndexByte(w, '=')+1:]
			if shellOptsValueHasXtrace(value) {
				return true
			}
		case assignmentRe.MatchString(w):
			skipFlags = false
		default:
			return false
		}
	}
	return false
}

// shellOptsValueHasXtrace reports whether a SHELLOPTS value, a colon
// separated option list, contains xtrace as one element.
func shellOptsValueHasXtrace(value string) bool {
	for _, opt := range strings.Split(value, ":") {
		if opt == "xtrace" {
			return true
		}
	}
	return false
}

// blankSubshells returns script with the inside of every ( … ) subshell
// that opens and closes on one line replaced by spaces.
// $( … ) command substitutions and quoted text are left as they are.
func blankSubshells(script string) string {
	b := []byte(script)
	var stack []int // start of each open bracket; -1 for $( and ${
	var quote byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' {
				i++
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '(' && i > 0 && (b[i-1] == '$' || b[i-1] == '<' || b[i-1] == '>'):
			stack = append(stack, -1)
		case c == '(':
			stack = append(stack, i)
		case c == ')' && len(stack) > 0:
			start := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			// Only a subshell on one line: one that spans a block can hold
			// a whole script, all of it traced.
			if start < 0 || len(stack) > 0 || strings.Contains(script[start:i], "\n") {
				continue
			}
			for j := start + 1; j < i; j++ {
				b[j] = ' '
			}
		}
	}
	return string(b)
}
