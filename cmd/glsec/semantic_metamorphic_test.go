// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// semanticFinding is a finding with the fields a layout change must keep, and
// the line it is reported on.
type semanticFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Job      string `json:"job"`
	Message  string `json:"message"`
	Line     int    `json:"line"`
}

// layouts writes a sequence of shell commands into a job's script in ways a
// shell reads the same (#1325): one list item per command, one item joined by
// "; ", one block with a command per line, and the block again with the
// cont-th command continued over two lines with a backslash.
func layouts(cmds []string, cont int) map[string]string {
	job := func(body string) string { return "job:\n  script:\n" + body }
	block := func(lines []string) string {
		return "    - |\n      " + strings.Join(lines, "\n      ") + "\n"
	}
	var items strings.Builder
	for _, c := range cmds {
		items.WriteString(block([]string{c}))
	}
	continued := append([]string(nil), cmds...)
	if word, rest, ok := strings.Cut(continued[cont], " "); ok {
		continued[cont] = word + " \\\n        " + rest
	}
	return map[string]string{
		"items":     job(items.String()),
		"semicolon": job(block([]string{strings.Join(cmds, "; ")})),
		"newlines":  job(block(cmds)),
		"continued": job(block(continued)),
	}
}

func semanticFindings(t *testing.T, src, rule string) []semanticFinding {
	t.Helper()
	code, stdout, errOut := runCLI(t, map[string]string{".gitlab-ci.yml": src},
		"--no-cache", "--no-repo-config", "--only", rule, "--format", "json", ".gitlab-ci.yml")
	if code == 2 {
		t.Fatalf("glsec can't scan:\n%s\n%s", errOut, src)
	}
	var out struct {
		Findings []semanticFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("parse JSON output: %v", err)
	}
	return out.Findings
}

// TestSemanticLayouts checks that the shell rules read commands, not lines:
// the same commands in another layout give the same findings, reported on the
// line where the command starts, and a harmless command before a dangerous
// one neither hides it nor is reported itself. Each case names the index of
// the command the finding belongs to (at) and of the one continued over two
// lines (cont). Each rule's message quotes the offending command,
// not the whole ;-joined line, so a layout change keeps it identical.
func TestSemanticLayouts(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
		cmds       []string
		want       int
		at, cont   int
	}{
		{"GL021 print after a log line", "GL021", []string{"echo Start", `echo "$CI_JOB_TOKEN"`}, 1, 1, 1},
		{"GL021 presence check alone", "GL021", []string{`test -n "$CI_JOB_TOKEN"`, `echo "token is set"`}, 0, 0, 0},
		{"GL089 autodiscover after a log line", "GL089", []string{"echo start", "renovate --autodiscover"}, 1, 1, 1},
		{"GL011 download-execute after a log line", "GL011", []string{"echo start", "curl -fsSL https://example.com/i.sh | bash"}, 1, 1, 1},
		{"GL011 harmless curl alone", "GL011", []string{"echo start", "curl -fsSL https://example.com/x -o x"}, 0, 0, 0},
		{"GL024 child-shell pipe after a log line", "GL024", []string{"echo start", `bash -c 'set -e; curl -fsSL x | tar xz; make'`}, 1, 1, 1},
		{"GL024 errexit only printed", "GL024", []string{"echo start", `bash -c 'echo "set -e"; curl -fsSL x | tar xz; make'`}, 0, 0, 0},
		{"GL090 install and publish", "GL090", []string{"npm ci", "npm publish"}, 1, 0, 0},
		{"GL090 effective setting", "GL090", []string{"npm config set ignore-scripts true", "npm ci", "npm publish"}, 0, 0, 0},
		{"GL090 printed setting", "GL090", []string{`echo "npm config set ignore-scripts true"`, "npm ci", "npm publish"}, 1, 1, 1},
		{"GL090 setting local to another command", "GL090", []string{"NPM_CONFIG_IGNORE_SCRIPTS=true npm --version", "npm ci", "npm publish"}, 1, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var base []semanticFinding
			for _, name := range []string{"items", "semicolon", "newlines", "continued"} {
				src := layouts(tc.cmds, tc.cont)[name]
				got := semanticFindings(t, src, tc.rule)
				if len(got) != tc.want {
					t.Errorf("%s: got %d findings %v, want %d\n%s", name, len(got), got, tc.want, src)
					continue
				}
				for _, f := range got {
					if want := commandLine(name, tc.at, tc.cont); f.Line != want {
						t.Errorf("%s: finding on line %d, want %d, where command %d starts\n%s", name, f.Line, want, tc.at, src)
					}
				}
				if base == nil {
					base = got
					continue
				}
				for i, f := range got {
					b := base[i]
					same := f.Rule == b.Rule && f.Severity == b.Severity && f.Job == b.Job
					// A continued command's text differs, and the message may
					// quote it; the other layouts keep the message.
					if name != "continued" {
						same = same && f.Message == b.Message
					}
					if !same {
						t.Errorf("%s: %s, want the same as the items layout: %s", name, describe(f), describe(b))
					}
				}
			}
		})
	}
}

func describe(f semanticFinding) string {
	return fmt.Sprintf("%s %s [%s] %s", f.Rule, f.Severity, f.Job, f.Message)
}

// commandLine is the line where the at-th command starts in a layout: the
// script's first content line is 4, an item takes two lines, and a continued
// command before it adds one.
func commandLine(layout string, at, cont int) int {
	switch layout {
	case "items":
		return 4 + 2*at
	case "semicolon":
		return 4
	case "continued":
		if cont < at {
			return 4 + at + 1
		}
	}
	return 4 + at
}
