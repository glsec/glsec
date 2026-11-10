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

type gl062 struct{}

var GL062 = &gl062{}

func (r *gl062) ID() string { return "GL062" }

// envFullDumpRe matches a command that prints the entire environment:
// printenv, bare env (also env -0/--null), cat /proc/self/environ, bare set,
// export/export -p, declare/typeset bare or with only -p/-x, and the
// PowerShell env: enumeration (see psEnvDump). The command must sit at a
// shell command boundary and be followed immediately by end-of-line or a
// shell separator, so `printenv VAR`, `env VAR=v cmd`, `set -e`,
// `export FOO=bar`, `declare -a arr=(…)` and `Get-ChildItem env:PATH` are not
// matched.
// (?m): in a multi-line block the command can be on any line (#975).
var envFullDumpRe = mustCompilePrefiltered(`(?m)(?:^|[;&|(])\s*(?:/usr/bin/|/bin/)?(` +
	`printenv|env(?:\s+(?:-0|--null))?|` +
	`cat\s+/proc/(?:self|\$\$|[0-9]+|\*|\[0-9\]\*|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)/environ|` +
	`set|export(?:\s+-p)?|(?:declare|typeset)(?:\s+-[px]+)?|` +
	psEnvDump +
	`)\s*(?:$|[;&|#)])`)

// Keep the original env/printenv matching and message, including commands
// inside a quoted sh -c payload. Quote suppression applies only to new forms.
var legacyEnvFullDumpRe = mustCompilePrefiltered(`(?m)(?:^|[;&|(])\s*(?:/usr/bin/|/bin/)?(?:printenv|env)\s*(?:$|[;&|#)])`)

// procLoopEnvironRe matches a loop that enumerates process-environment files,
// for p in /proc/[0-9]*/environ; do … (#1345). Group 1 is the loop variable,
// read later with < "$p". A single process (self/$$/<pid>) stays with the
// cat form in envFullDumpRe.
var procLoopEnvironRe = mustCompilePrefiltered(`(?m)\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b[^;\n]*?/proc/(?:\*|\[0-9\]\*|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|[0-9]+|self|\$\$)/environ`)

// doneWordRe ends a for/while loop body.
var doneWordRe = mustCompilePrefiltered(`\bdone\b`)

// findEnvFullDump keeps a closing parenthesis as a boundary only when an
// opening parenthesis precedes it. Otherwise set) and export) are case labels.
// Legacy env/printenv retain their existing boundary behaviour (#1161).
// The prefix is scanned once across all matches, without parsing shell syntax.
func findEnvFullDump(text string, depth int) []int {
	scanned := 0
	for _, m := range envFullDumpRe.FindAllStringSubmatchIndex(text, -1) {
		depth = envDumpParenDepth(text[scanned:m[1]-1], depth)
		scanned = m[1] - 1
		command := text[m[2]:m[3]]
		if text[m[1]-1] == ')' && depth == 0 && command != "env" && command != "printenv" {
			continue
		}
		return m
	}
	return nil
}

func envDumpParenDepth(text string, depth int) int {
	for _, c := range text {
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}

// psEnvDump matches a PowerShell command that lists every variable: the
// Get-ChildItem aliases and Get-Item, with env: or env:* as the whole path
// argument. The env: drive is case insensitive. `$env:NAME` and
// `Get-ChildItem env:NAME` print a single variable and are not matched. Used
// by GL062 and GL014 (#1161).
const psEnvDump = `(?i:(?:gci|get-childitem|dir|ls|get-item)\s+(?:-path\s+)?env:(?:\*)?)`

func (r *gl062) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		// Comments go first: an apostrophe in one would open a quote that
		// hides every later line of the block, and a block that starts with
		// one may still run a dump below it (#1176).
		v := blankCaseLabels(blankShellComments(line.Value))
		if strings.TrimSpace(v) == "" {
			return
		}
		// Preserve legacy matching in sh -c payloads. Mask only the new forms,
		// so `echo "hello; set; done"` is not read as a dump (#1161).
		if !mayRunShellC(v) && !wrapperWordRe.MatchString(v) && !legacyEnvFullDumpRe.MatchString(v) && !envFullDumpRe.MatchString(maskShellQuotes(v)) && !procLoopEnvironRe.MatchString(v) {
			return
		}
		cmds := shellCommands(v)
		depth := 0
		for ci, cmd := range cmds {
			text := unwrappedLine(cmd.text)
			masked := maskShellQuotes(text)
			m := findEnvFullDump(masked, depth)
			depth = envDumpParenDepth(masked, depth)
			loc := legacyEnvFullDumpRe.FindStringIndex(text)
			dump := "printenv/env with no arguments"
			legacy := true
			if m != nil && (loc == nil || m[0] < loc[0]) {
				loc = m[:2]
				dump = text[m[2]:m[3]]
				legacy = false
			}
			// Output captured by $(…) or backticks goes to a variable or an
			// argument, not to the log: X=$(env | grep …), for v in $(env …).
			if loc == nil || strings.Contains(text[:loc[1]], "$(") || strings.Contains(text[:loc[1]], "`") {
				continue
			}
			// The pipeline's output written to a file doesn't reach the log.
			last := ci
			for last < len(cmds)-1 && cmds[last].piped {
				last++
			}
			if stdoutRedirectRe.MatchString(maskSingleQuoted(cmds[last].text)) || psFileWriteRe.MatchString(cmds[last].text) {
				continue
			}
			msg := fmt.Sprintf("%s dumps every environment variable to the job log, including CI/CD secrets and tokens that may not be reliably masked — print only the specific variables you need", dump)
			if cmd.piped && ci+1 < len(cmds) {
				if filter, pattern, names, ok := envFilter(cmds[ci+1].text); ok {
					if narrowEnvFilter(names) {
						continue // env | grep THREADS: one variable, like printenv THREADS (#996)
					}
					name := dump
					if legacy {
						name = "env/printenv"
					}
					msg = fmt.Sprintf("%s filtered with %s %q prints every variable that matches, including CI/CD secrets such as CI_JOB_TOKEN or CI_REGISTRY_PASSWORD whose names match — print only the specific variables you need", name, filter, pattern)
				}
			}
			f := finding.Finding{
				RuleID:   "GL062",
				Severity: finding.Warn,
				Job:      job,
				Message:  msg,
				File:     file,
				Line:     parser.ScalarContentLine(line, cmd.line),
			}
			if cmd.line == 0 {
				f.Col = line.Column
			}
			findings = append(findings, f)
			return
		}
		if at, ok := procLoopEnvironDump(v); ok {
			f := finding.Finding{
				RuleID:   "GL062",
				Severity: finding.Warn,
				Job:      job,
				Message:  "a loop over /proc/<glob>/environ dumps every process's environment to the job log — on a shared or non-ephemeral runner this can expose other jobs' CI/CD secrets; read only the specific variables you need",
				File:     file,
				Line:     parser.ScalarContentLine(line, at),
			}
			if at == 0 {
				f.Col = line.Column
			}
			findings = append(findings, f)
		}
	})
	return findings
}

// procLoopEnvironDump reports a loop that reads every process's environment
// through /proc/<glob>/environ and whose output reaches the job log: the
// motivating credential-harvest shape
//
//	for p in /proc/[0-9]*/environ; do tr '\0' '\n' < "$p" …; done | base32
//
// It returns the item-relative line of the loop. Output redirected to a file
// or captured in a command substitution, and a loop whose variable is never
// read with < "$p", are not reported (#1345).
func procLoopEnvironDump(item string) (int, bool) {
	masked := maskShellQuotes(item)
	m := procLoopEnvironRe.FindStringSubmatchIndex(masked)
	if m == nil {
		return 0, false
	}
	varName := item[m[2]:m[3]]
	read := regexp.MustCompile(`<\s*["']?\$\{?` + regexp.QuoteMeta(varName) + `(?:[^A-Za-z0-9_]|$)`)
	if !read.MatchString(item[m[1]:]) {
		return 0, false // the loop variable is never read as a file
	}
	// Captured in a command substitution: the loop's output goes to a
	// variable, not the log.
	if opensSubstitution(item[:m[0]]) {
		return 0, false
	}
	// The dump's own pipeline, up to the end of the line that closes the
	// loop, writes to a file: its output doesn't reach the log. 2>/dev/null
	// only drops stderr, and a > elsewhere in a multi-section block is another
	// command's.
	sinkEnd := len(item)
	if d := doneWordRe.FindStringIndex(masked[m[1]:]); d != nil {
		if nl := strings.IndexByte(item[m[1]+d[1]:], '\n'); nl >= 0 {
			sinkEnd = m[1] + d[1] + nl
		}
	}
	if stdoutRedirectRe.MatchString(maskShellQuotes(item[m[0]:sinkEnd])) {
		return 0, false
	}
	return strings.Count(item[:m[0]], "\n"), true
}

// PowerShell forms of a pipeline stage after an env: listing (#1172).
var (
	// psFileWriteRe matches a cmdlet that takes the pipeline's output to a
	// file. Tee-Object writes to the log as well, so it isn't one.
	psFileWriteRe = mustCompilePrefiltered(`(?i)^(?:out-file|set-content|add-content)\b`)
	// psSelectStringRe matches Select-String with one pattern and no other
	// option. Group 1 is the pattern.
	psSelectStringRe = mustCompilePrefiltered(`(?i)^(?:select-string|sls)\s+(?:-pattern\s+)?["']?([^\s"']+)["']?$`)
	// psWhereNameRe matches Where-Object on the name alone, as a comparison
	// or a script block. A test of $_.Value selects by content, and anything
	// more than one comparison doesn't match.
	psWhereNameRe = mustCompilePrefiltered(`(?i)^(?:where-object|where|\?)\s+(?:name\s+-i?(?:eq|match|like)\s+["']?([^\s"']+)["']?|\{\s*\$_\.name\s+-i?(?:eq|match|like)\s+["']?([^\s"']+)["']?\s*\})$`)
)

// envFilter returns the filter in a pipeline stage after a dump, named for the
// message, the pattern it selects variables by, and the alternatives a
// variable name has to match; names is empty for a filter that may print any
// variable, such as grep -v.
func envFilter(cmd string) (filter, pattern string, names []string, ok bool) {
	if p, names, ok := grepPattern(cmd); ok {
		return "grep", p, names, true
	}
	if m := psSelectStringRe.FindStringSubmatch(cmd); m != nil {
		return "Select-String", m[1], []string{m[1]}, true
	}
	if m := psWhereNameRe.FindStringSubmatch(cmd); m != nil {
		return "Where-Object", m[1] + m[2], []string{m[1] + m[2]}, true
	}
	return "", "", nil, false
}

// grepPattern returns the patterns a grep, egrep or fgrep command filters by,
// joined for the message, and their alternatives: every -e, split at | for
// -E and at \| for a basic regexp (#1277). An inverted match has none, since
// it prints every variable but the ones named.
func grepPattern(cmd string) (pattern string, names []string, ok bool) {
	words := commandWords(cmd)
	name := commandName(words)
	switch name {
	case "grep", "egrep", "fgrep":
	default:
		return "", nil, false
	}
	extended, fixed, inverted := name == "egrep", name == "fgrep", false
	var patterns []string
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "-e" && i+1 < len(words):
			i++
			patterns = append(patterns, words[i])
		case w == "--extended-regexp":
			extended = true
		case w == "--fixed-strings":
			fixed = true
		case w == "--invert-match":
			inverted = true
		case strings.HasPrefix(w, "--"):
		case strings.HasPrefix(w, "-"):
			extended = extended || strings.Contains(w, "E")
			fixed = fixed || strings.Contains(w, "F")
			inverted = inverted || strings.Contains(w, "v")
		case len(patterns) == 0:
			patterns = append(patterns, w)
		}
	}
	if len(patterns) == 0 {
		return "", nil, false
	}
	if !inverted {
		for _, p := range patterns {
			names = append(names, grepAlternatives(p, extended, fixed)...)
		}
	}
	return strings.Join(patterns, " "), names, true
}

// grepAlternatives splits a pattern into the names it matches: ^(A|B)= is A
// and B.
func grepAlternatives(p string, extended, fixed bool) []string {
	sep := `\|`
	switch {
	case fixed:
		return []string{p}
	case extended:
		sep = "|"
		if t := strings.TrimSuffix(strings.TrimPrefix(p, "^"), "="); strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
			p = t[1 : len(t)-1]
		}
	}
	return strings.Split(p, sep)
}

// narrowEnvFilter reports a filter that selects variables a dump prints
// harmlessly: every alternative is a literal name without a secret-like
// word, not the CI prefix whose variables include the job's tokens.
func narrowEnvFilter(names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if !narrowEnvName(n) {
			return false
		}
	}
	return true
}

func narrowEnvName(pattern string) bool {
	name := strings.TrimSuffix(strings.TrimPrefix(pattern, "^"), "=")
	if !envFilterNameRe.MatchString(name) || strings.HasPrefix(strings.ToUpper(name), "CI") || strings.HasPrefix(strings.ToUpper(name), "GITLAB") {
		return false
	}
	upper := strings.ToUpper(name)
	for _, w := range []string{"TOKEN", "SECRET", "PASS", "KEY", "CRED", "AUTH", "PRIVATE"} {
		if strings.Contains(upper, w) {
			return false
		}
	}
	return true
}

var envFilterNameRe = mustCompilePrefiltered(`^[A-Za-z_][A-Za-z0-9_]{2,}$`)

// stdoutRedirectRe matches stdout redirected to a file (> f, >> f, 1> f),
// not 2> or >&2.
var stdoutRedirectRe = mustCompilePrefiltered(`(?:^|[^0-9&>])1?>>?\s*[^&\s]`)
