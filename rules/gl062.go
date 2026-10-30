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
		cmds := shellCommands(v)
		for ci, cmd := range cmds {
			loc := envFullDumpRe.FindStringIndex(cmd.text)
			// Output captured by $(…) or backticks goes to a variable or an
			// argument, not to the log: X=$(env | grep …), for v in $(env …).
			if loc == nil || strings.Contains(cmd.text[:loc[1]], "$(") || strings.Contains(cmd.text[:loc[1]], "`") {
				continue
			}
			// The pipeline's output written to a file doesn't reach the log.
			last := ci
			for last < len(cmds)-1 && cmds[last].piped {
				last++
			}
			if stdoutRedirectRe.MatchString(maskSingleQuoted(cmds[last].text)) {
				continue
			}
			msg := "printenv/env with no arguments dumps every environment variable to the job log, including CI/CD secrets and tokens that may not be reliably masked — print only the specific variables you need"
			if cmd.piped && ci+1 < len(cmds) {
				if pattern, ok := grepPattern(cmds[ci+1].text); ok {
					if narrowEnvFilter(pattern) {
						continue // env | grep THREADS: one variable, like printenv THREADS (#996)
					}
					msg = fmt.Sprintf("env/printenv filtered with grep %q prints every variable that matches, including CI/CD secrets such as CI_JOB_TOKEN or CI_REGISTRY_PASSWORD whose names match — print only the specific variables you need", pattern)
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
	})
	return findings
}

// grepPattern returns the pattern a grep, egrep or fgrep command filters by.
func grepPattern(cmd string) (string, bool) {
	words := commandWords(cmd)
	switch commandName(words) {
	case "grep", "egrep", "fgrep":
	default:
		return "", false
	}
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "-e" && i+1 < len(words):
			return words[i+1], true
		case strings.HasPrefix(w, "-"):
		default:
			return w, true
		}
	}
	return "", false
}

// narrowEnvFilter reports a grep pattern that selects variables a dump
// prints harmlessly: a literal name without a secret-like word, not the CI
// prefix whose variables include the job's tokens.
func narrowEnvFilter(pattern string) bool {
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

var envFilterNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{2,}$`)

// stdoutRedirectRe matches stdout redirected to a file (> f, >> f, 1> f),
// not 2> or >&2.
var stdoutRedirectRe = regexp.MustCompile(`(?:^|[^0-9&>])1?>>?\s*[^&\s]`)
