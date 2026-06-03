package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl021 struct{}

var GL021 = &gl021{}

func (r *gl021) ID() string { return "GL021" }

var (
	// printCmdRe matches shell output commands.
	printCmdRe = regexp.MustCompile(`\b(?:echo|printf|print)\b`)

	// secretVarRe matches CI variable references whose names end with a secret-indicating suffix.
	secretVarRe = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*(?:_TOKEN|_SECRET|_PASSWORD|_PASSWD|_PASS|_PWD|_KEY|_CREDENTIAL|_CERT)\}?`)

	// safeCheckRe matches patterns that reference the variable without printing its value:
	// length checks (-n "$VAR", test -n "$VAR"), default expansions (${VAR:-}, ${VAR:+}).
	safeCheckRe = regexp.MustCompile(`\[\s*(?:-n|-z)\s+|\btest\s+-[nz]\b|:\-|:\+`)

	// singleQuotedRe matches single-quoted spans, whose contents the shell does
	// not expand (so a secret reference inside them is literal text).
	singleQuotedRe = regexp.MustCompile(`'[^']*'`)
)

func (r *gl021) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"before_script", "script", "after_script"} {
			node := parser.FindKey(job, key)
			if node == nil || node.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range node.Content {
				if item.Kind != yaml.ScalarNode {
					continue
				}
				// Match per physical line: a `|` block scalar is one item but
				// many commands.
				for i, line := range strings.Split(item.Value, "\n") {
					match, ok := printedSecret(line)
					if !ok {
						continue
					}
					findings = append(findings, finding.Finding{
						RuleID:   "GL021",
						Severity: finding.Warn,
						Job:      name.Value,
						Message:  fmt.Sprintf("script prints secret variable %s — value may appear in job logs", match),
						File:     file,
						Line:     parser.ScalarContentLine(item, i),
						Col:      item.Column,
					})
				}
			}
		}
	})

	return findings
}

// printedSecret reports whether a script line actually prints a secret variable
// to stdout/stderr (i.e. the job log). It returns false when the printed value
// is instead redirected to a file, piped into another command, captured by a
// command/process substitution, or single-quoted (not expanded) — none of which
// reach the log absent debug tracing.
func printedSecret(line string) (string, bool) {
	// Single-quoted spans are literal; blank them so a `$VAR` inside one does
	// not count as a reference.
	s := singleQuotedRe.ReplaceAllString(line, " ")
	if safeCheckRe.MatchString(s) {
		return "", false
	}

	for _, loc := range secretVarRe.FindAllStringIndex(s, -1) {
		start, end := loc[0], loc[1]

		// Find the command segment the secret belongs to (split on shell
		// command separators).
		left := start - 1
		for left >= 0 && !isShellSep(s[left]) {
			left--
		}
		right := end
		for right < len(s) && !isShellSep(s[right]) {
			right++
		}

		// The secret must be an argument of a print command in this segment.
		if !printCmdRe.MatchString(s[left+1 : start]) {
			continue
		}
		seg := s[left+1 : right]
		// Output redirected to a file (`>` / `>>`): not logged.
		if strings.Contains(seg, ">") {
			continue
		}
		// Output piped into another command: not logged.
		if right < len(s) && s[right] == '|' {
			continue
		}
		// Inside `$(…)` or `<(…)` command/process substitution: captured, not logged.
		if left >= 0 && s[left] == '(' && (left == 0 || s[left-1] == '$' || s[left-1] == '<') {
			continue
		}
		return s[start:end], true
	}
	return "", false
}

// isShellSep reports whether b separates shell commands (pipeline, list, or
// substitution boundaries). Note `{`/`}` are intentionally excluded: they close
// `${VAR}` brace expansions far more often than they group commands, and
// treating them as separators truncates a segment mid-variable (hiding a later
// redirect or pipe).
func isShellSep(b byte) bool {
	switch b {
	case '|', '&', ';', '(', ')':
		return true
	}
	return false
}
