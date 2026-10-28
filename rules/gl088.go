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

type gl088 struct{}

var GL088 = &gl088{}

func (r *gl088) ID() string { return "GL088" }

// scriptOnlyInVariables names the GL006 patterns that are not specific enough
// on a command line: a script that checks a key file's type contains the same
// text as the key itself.
var scriptOnlyInVariables = map[string]bool{
	"GCP service account key": true,
}

// boundaryClass is a character that can't continue a token, used on both
// sides because RE2 has no lookaround.
const boundaryClass = `[^A-Za-z0-9_-]`

type scriptSecretPattern struct {
	name string
	// prefix is the literal every token of this type starts with, empty when
	// there is none. Most script lines contain none of them, and a
	// strings.Contains is far cheaper than the regexp (#870).
	prefix string
	re     *regexp.Regexp
}

// scriptSecretPatterns are GL006's patterns with the whole-value anchors
// replaced by token boundaries, so they find a token inside a command (#737).
var scriptSecretPatterns = func() []scriptSecretPattern {
	out := make([]scriptSecretPattern, 0, len(secretPatterns))
	for _, p := range secretPatterns {
		if scriptOnlyInVariables[p.name] {
			continue
		}
		expr := p.re.String()
		flags := ""
		if strings.HasPrefix(expr, "(?i)") {
			flags, expr = "(?i)", strings.TrimPrefix(expr, "(?i)")
		}
		expr = strings.TrimSuffix(strings.TrimPrefix(expr, "^"), "$")
		prefix := ""
		if flags == "" {
			prefix, _ = regexp.MustCompile(expr).LiteralPrefix()
		}
		out = append(out, scriptSecretPattern{name: p.name, prefix: prefix, re: regexp.MustCompile(
			flags + `(?:^|` + boundaryClass + `)(` + expr + `)(?:$|` + boundaryClass + `)`)})
	}
	return out
}()

func (r *gl088) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(item *yaml.Node, file, job string) {
		for i, line := range strings.Split(item.Value, "\n") {
			for _, name := range scriptSecrets(line) {
				f := finding.Finding{
					RuleID:   "GL088",
					Severity: finding.Error,
					Job:      job,
					Message:  fmt.Sprintf("script line contains a hardcoded %s — anyone who can read the repository can use it; store it in a masked CI/CD variable and reference that instead", name),
					File:     file,
					Line:     parser.ScalarContentLine(item, i),
				}
				if i == 0 {
					f.Col = item.Column
				}
				findings = append(findings, f)
			}
		}
	})
	return findings
}

// scriptSecrets returns the type of every token in line, once per token: where
// two patterns match the same text, the first one in GL006's order names it.
func scriptSecrets(line string) []string {
	var names []string
	var taken [][2]int
	for _, p := range scriptSecretPatterns {
		if p.prefix != "" && !strings.Contains(line, p.prefix) {
			continue
		}
		// The boundary after a token is part of the match, so the next search
		// starts at the token's end: two tokens may share one separator.
		for pos := 0; pos < len(line); {
			m := p.re.FindStringSubmatchIndex(line[pos:])
			if m == nil {
				break
			}
			start, end := pos+m[2], pos+m[3]
			pos = end
			if looksLikePlaceholder(line[start:end]) || overlaps(taken, start, end) {
				continue
			}
			taken = append(taken, [2]int{start, end})
			names = append(names, p.name)
		}
	}
	return names
}

func overlaps(spans [][2]int, start, end int) bool {
	for _, s := range spans {
		if start < s[1] && s[0] < end {
			return true
		}
	}
	return false
}
