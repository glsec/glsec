package rules

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl068 struct{}

var GL068 = &gl068{}

func (r *gl068) ID() string { return "GL068" }

// setCmdRe captures the argument list of each `set` command on a line, bounded
// by statement separators so `echo set -x` or `unset` are not matched.
var setCmdRe = regexp.MustCompile(`(?:^|[;&|(])\s*set\s+([^;&|)]*)`)

func (r *gl068) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		if strings.HasPrefix(strings.TrimSpace(line.Value), "#") {
			return
		}
		if !lineEnablesXtrace(line.Value) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL068",
			Severity: finding.Warn,
			Job:      job,
			Message:  "set -x enables shell xtrace — every command is printed to the job log after variable expansion, so any command referencing a secret (token in a git URL, Authorization header, --key flag) leaks it in plaintext; drop the x (use set -euo pipefail) or scope tracing with set +x around secret-touching commands",
			File:     file,
			Line:     line.Line,
			Col:      line.Column,
		})
	})
	return findings
}

// lineEnablesXtrace reports whether the net shell option state at the end of the
// line has xtrace enabled. Tracking the net effect means a self-contained
// `set -x …; set +x` block on one line (the documented way to scope tracing to a
// non-secret section) is not flagged, while a bare `set -x` is.
func lineEnablesXtrace(line string) bool {
	enabled := false
	touched := false
	for _, m := range setCmdRe.FindAllStringSubmatch(line, -1) {
		if on, ok := xtraceArg(m[1]); ok {
			enabled = on
			touched = true
		}
	}
	return touched && enabled
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
