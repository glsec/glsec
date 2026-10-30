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

type gl021 struct{}

var GL021 = &gl021{}

func (r *gl021) ID() string { return "GL021" }

var (
	// assignRe matches a leading shell env assignment (VAR=value) that precedes
	// a command without being one.
	assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

	// gl021VarRefRe also accepts PowerShell's $env:NAME and ${env:NAME}.
	// The env: drive is case insensitive; the capture is the variable name.
	gl021VarRefRe = regexp.MustCompile(`\$\{?(?i:env:)?([A-Za-z_][A-Za-z0-9_]*)\}?`)

	// secretNameRe matches names carrying a secret indicator after at least one
	// character, anywhere in the name: SECRET_KEY_BASE and DEPLOY_TOKEN alike.
	secretNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:_TOKEN|_SECRET|_PASSWORD|_PASSWD|_PASS|_PWD|_KEY|_CREDENTIAL|_CERT)`)

	// nonSecretSuffixRe matches a final name segment that names something
	// about the secret rather than the secret itself: GPG_KEY_ID,
	// DOCKER_PASSWORD_FILE, DEPLOY_TOKENIZER_URL (#579). DIR also counts
	// without an underscore, as in DOCKER_TLS_CERTDIR.
	nonSecretSuffixRe = regexp.MustCompile(`(?:_(?:ID|URL|URI|PATH|FILE|NAME|HOST|USER|USERNAME|TYPE|LENGTH|EXPIRES_AT|VERSION|PACKAGE|ENDPOINT|DOMAIN|PORT|REGION|ENABLED|MODE)|DIR)$`)

	// safeCheckRe matches patterns that reference the variable without printing its value:
	// length checks (-n "$VAR", test -n "$VAR"), default expansions (${VAR:-}, ${VAR:+}).
	safeCheckRe = regexp.MustCompile(`\[\s*(?:-n|-z)\s+|\btest\s+-[nz]\b|:\-|:\+`)

	// singleQuotedRe matches single-quoted spans, whose contents the shell does
	// not expand (so a secret reference inside them is literal text).
	singleQuotedRe = regexp.MustCompile(`'[^']*'`)

	// A direct file redirect of PowerShell's information stream (or all
	// streams) suppresses host output. A merge such as 6>&1 is not a file.
	gl021InfoFileRedirectRe = regexp.MustCompile(`^(?:6|\*)>>?\s*[^&\s]`)
)

func (r *gl021) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	// An item shared by several jobs through an anchor is checked once (#766).
	seen := map[*yaml.Node]bool{}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		scriptNodes := []*yaml.Node{
			parser.FindKey(job, "before_script"),
			parser.FindKey(job, "script"),
			parser.FindKey(job, "after_script"),
			hookScriptNode(job),
		}
		scriptNodes = append(scriptNodes, parser.RunStepBlocks(job)...)
		for _, node := range scriptNodes {
			if !isScriptList(node) {
				continue
			}
			for _, item := range node.Content {
				if item.Kind != yaml.ScalarNode || seen[item] {
					continue
				}
				seen[item] = true
				// Match per line: a `|` block scalar is one item but many
				// commands. A backslash continuation belongs to its line, so a
				// redirect or pipe on the next physical line still counts.
				for _, l := range logicalLines(item.Value) {
					i, line := l.line, l.text
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
// reach the log absent debug tracing. PowerShell's information stream is
// separate from success output and needs its own redirection.
func printedSecret(line string) (string, bool) {
	// Single-quoted spans are literal. Keep an empty quoted placeholder so a
	// filename such as 6> 'private log.txt' still has a redirection target.
	s := singleQuotedRe.ReplaceAllString(line, "''")
	if safeCheckRe.MatchString(s) {
		return "", false
	}

	for _, loc := range gl021VarRefRe.FindAllStringSubmatchIndex(s, -1) {
		name := s[loc[2]:loc[3]]
		powerShell := strings.Contains(s[loc[0]:loc[2]], ":")
		if powerShell {
			name = strings.ToUpper(name) // Windows environment names are case insensitive.
		}
		if !isSecretName(name) {
			continue
		}
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

		// The secret must be an argument of a print command that is the
		// segment's command — not an `echo` buried inside a quoted argument to
		// another command (e.g. git config credential.helper "!echo $TOKEN").
		command := segmentPrintCommand(s[left+1 : start])
		if command == "" {
			continue
		}
		if powerShell || strings.HasPrefix(command, "write") {
			escapeStart := start
			for escapeStart > 0 && s[escapeStart-1] == '`' {
				escapeStart--
			}
			if (start-escapeStart)%2 != 0 {
				continue // An unpaired backtick makes the variable reference literal.
			}
		}
		seg := s[left+1 : right]
		if command == "write-host" || command == "write-information" {
			if informationRedirected(seg) {
				continue
			}
			return varRefText(s[start:end]), true
		}
		// Output redirected to a file (`>` / `>>`): not logged.
		if strings.Contains(seg, ">") {
			continue
		}
		// Output piped into another command: not logged.
		if right < len(s) && s[right] == '|' {
			continue
		}
		// Inside `$(…)` or `<(…)` command/process substitution: captured, not
		// logged. A bare `(` is a subshell, whose output does reach the log.
		if left > 0 && s[left] == '(' && (s[left-1] == '$' || s[left-1] == '<') {
			continue
		}
		return varRefText(s[start:end]), true
	}
	return "", false
}

// informationRedirected checks for a direct information-stream file redirect,
// ignoring operators inside quoted or backtick-escaped argument text.
func informationRedirected(seg string) bool {
	var quote byte
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c == '`':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case (c == '6' || c == '*') && (i == 0 || isShellSpace(seg[i-1])):
			if gl021InfoFileRedirectRe.MatchString(seg[i:]) {
				return true
			}
		}
	}
	return false
}

// isSecretName reports whether a variable name looks like it holds a secret
// value: it carries a secret indicator and doesn't end in a segment such as
// _ID or _URL that names something else.
func isSecretName(name string) bool {
	return secretNameRe.MatchString(name) && !nonSecretSuffixRe.MatchString(name) && !nonSecretPredefined[name]
}

// nonSecretPredefined are predefined variables whose names look secret but
// whose values are not: CI_RUNNER_SHORT_TOKEN is documented as an identifier.
var nonSecretPredefined = map[string]bool{"CI_RUNNER_SHORT_TOKEN": true}

// predefinedSecrets are GitLab's predefined credentials, which every job gets
// anyway.
var predefinedSecrets = map[string]bool{
	"CI_JOB_TOKEN": true, "CI_REGISTRY_PASSWORD": true, "CI_DEPENDENCY_PROXY_PASSWORD": true,
	"CI_DEPLOY_PASSWORD": true, "CI_JOB_JWT": true, "CI_JOB_JWT_V1": true, "CI_JOB_JWT_V2": true,
}

// isPredefinedVar reports whether name is a predefined variable that every
// job gets anyway: a predefined credential, or a CI_/GITLAB_ name that doesn't
// look secret. A secret-looking CI_ name such as CI_API_TOKEN is a project
// setting, not predefined.
func isPredefinedVar(name string) bool {
	if predefinedSecrets[name] {
		return true
	}
	return (strings.HasPrefix(name, "CI_") || strings.HasPrefix(name, "GITLAB_")) && !secretNameRe.MatchString(name)
}

// gl021PrefixTokens are leading tokens that introduce a command without being
// one (group/subshell openers and shell keywords). Env assignments are matched
// separately by assignRe.
var gl021PrefixTokens = map[string]bool{
	"{": true, "(": true, "!": true,
	"then": true, "do": true, "else": true, "elif": true,
}

// segmentPrintCommand returns the print command at the start of a segment,
// canonicalizing PowerShell command names. It skips leading env assignments and
// group/keyword openers, then checks the first real token — so an `echo` that
// only appears inside a quoted argument (the secret is not actually printed)
// does not count.
func segmentPrintCommand(segHead string) string {
	// Quoted placeholders preserve redirect targets, but command recognition
	// keeps the earlier behavior of treating single-quoted spans as blanks.
	segHead = strings.ReplaceAll(segHead, "''", " ")
	for _, tok := range strings.Fields(segHead) {
		if assignRe.MatchString(tok) || gl021PrefixTokens[tok] {
			continue
		}
		if tok == "echo" || tok == "printf" || tok == "print" {
			return tok
		}
		command := strings.ToLower(tok)
		switch command {
		case "write-host", "write-output", "write-information", "write":
			return command
		}
		return ""
	}
	return ""
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

// varRefText is a reference as the message shows it: ${NAME:0:4} matches as
// "${NAME", so the brace is closed (#977).
func varRefText(ref string) string {
	if strings.HasPrefix(ref, "${") && !strings.HasSuffix(ref, "}") {
		return ref + "}"
	}
	return ref
}
