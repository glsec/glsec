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

type gl002 struct{}

var GL002 = &gl002{}

func (r *gl002) ID() string { return "GL002" }

// userControlledVars are GitLab CI predefined variables whose values are
// set by external actors (commit authors, MR creators) and can contain
// shell metacharacters like $(...) or `...`.
var userControlledVars = []string{
	"CI_COMMIT_REF_NAME",
	"CI_COMMIT_BRANCH",
	"CI_COMMIT_TAG",
	"CI_COMMIT_TAG_MESSAGE",
	"CI_COMMIT_TITLE",
	"CI_COMMIT_MESSAGE",
	"CI_COMMIT_DESCRIPTION",
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"CI_MERGE_REQUEST_TITLE",
	"CI_MERGE_REQUEST_DESCRIPTION",
	"CI_PIPELINE_NAME",
	// Set only in external pull request pipelines (a project mirroring an
	// external repository). The source branch lives in the contributor's fork
	// on the external host, so the pull request author names it — the same
	// trust level as CI_MERGE_REQUEST_SOURCE_BRANCH_NAME, and not slugified.
	"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
	// Identity variables controlled directly by an untrusted contributor via
	// the commit or their own account profile. In fork MR pipelines these
	// reflect the external MR author. CI_COMMIT_AUTHOR is "Name <email>" taken
	// verbatim from the commit; GITLAB_USER_NAME/EMAIL are user-editable.
	// GITLAB_USER_LOGIN is deliberately excluded — its charset is restricted.
	"CI_COMMIT_AUTHOR",
	"GITLAB_USER_NAME",
	"GITLAB_USER_EMAIL",
	// Ends in @refs/heads/<branch> (GitLab 19.0), so it carries the branch name
	// the pusher chose, like CI_COMMIT_REF_NAME.
	"CI_CONFIG_REF_URI",
	// Free text on tag pipelines, the same trust as CI_COMMIT_TAG_MESSAGE.
	"CI_RELEASE_DESCRIPTION",
	// GitLab Duo flows: the comment that triggered the flow, and the JSON
	// context of the merge request, issue or epic (diff and comments).
	"AI_FLOW_INPUT",
	"AI_FLOW_CONTEXT",
}

// userVarRe matches any user-controlled variable reference ($VAR or ${VAR})
// followed by a word boundary so that e.g. $CI_COMMIT_REF_NAME_EXTRA is not matched.
var userVarRe = regexp.MustCompile(
	`\$\{?(` + strings.Join(userControlledVars, "|") + `)\b`,
)

// evalArgRe matches a command that parses its argument as code, up to and
// including the opening double quote of that argument. The outer shell
// expands variables inside the double quotes first, so the command then
// parses the attacker's value as code: quoting protects nothing here.
var evalArgRe = regexp.MustCompile(
	`(?:^|[\s;&|/(` + "`" + `])(eval|(?:ba|z|da|k)?sh[ \t]+(?:-[a-zA-Z]+[ \t]+)*-[a-zA-Z]*c|python[23]?(?:\.\d+)?[ \t]+(?:-[a-zA-Z]+[ \t]+)*-c|node[ \t]+(?:-e|--eval|-p|--print)|(?:perl|ruby)[ \t]+(?:-[a-zA-Z]+[ \t]+)*-[a-zA-Z]*e)[ \t]+"`,
)

func (r *gl002) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		for _, f := range checkScriptNode(node, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})
	return findings
}

func checkScriptNode(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			findings = append(findings, checkScriptLine(item, file)...)
		}
	}
	return findings
}

func checkScriptLine(node *yaml.Node, file string) []finding.Finding {
	masked := maskShellQuotes(node.Value)
	seen := map[string]bool{}
	findings := checkEvaluatedArgs(node, file, masked, seen)
	matches := userVarRe.FindAllStringSubmatchIndex(masked, -1)
	for _, loc := range matches {
		dollarPos := loc[0]
		varName := masked[loc[2]:loc[3]]
		if seen[varName] {
			continue
		}
		if notWordSplit(masked, dollarPos, loc[3]) {
			continue
		}
		seen[varName] = true
		at := strings.Count(masked[:dollarPos], "\n")
		f := finding.Finding{
			RuleID:   "GL002",
			Severity: finding.Warn,
			Message: fmt.Sprintf(
				"unquoted user-controlled variable $%s in script — value is %s and may contain shell metacharacters",
				varName, whoSets(varName),
			),
			File: file,
			Line: parser.ScalarContentLine(node, at),
		}
		if at == 0 {
			f.Col = node.Column
		}
		findings = append(findings, f)
	}
	return findings
}

// whoSets says who controls a user-controlled variable, for the message.
func whoSets(name string) string {
	switch {
	case strings.HasPrefix(name, "GITLAB_USER_"):
		return "taken from the profile of the user who started the pipeline"
	case strings.HasPrefix(name, "AI_FLOW_"):
		return "taken from the comment and merge request or issue that triggered the flow"
	case strings.Contains(name, "MERGE_REQUEST") || strings.Contains(name, "PULL_REQUEST"):
		return "set by the merge request author"
	case strings.Contains(name, "MESSAGE") || strings.Contains(name, "TITLE") || strings.Contains(name, "DESCRIPTION") || strings.Contains(name, "AUTHOR"):
		return "written by whoever creates the commit, tag or release"
	case strings.Contains(name, "REF_NAME") || strings.Contains(name, "BRANCH") || strings.Contains(name, "TAG") || name == "CI_CONFIG_REF_URI":
		return "the branch or tag name chosen by whoever pushed it"
	}
	return "set by commit authors"
}

// checkEvaluatedArgs reports user-controlled variables inside the
// double-quoted argument of a command that evaluates it as code (eval, sh -c,
// python -c, …). masked is maskShellQuotes(node.Value); masking keeps offsets,
// so the command is located on the masked copy, where a keyword inside a
// quoted string cannot match, and the argument is read from the raw value.
func checkEvaluatedArgs(node *yaml.Node, file, masked string, seen map[string]bool) []finding.Finding {
	var findings []finding.Finding
	for _, m := range evalArgRe.FindAllStringSubmatchIndex(masked, -1) {
		open := m[1] - 1
		end := strings.IndexByte(masked[open+1:], '"')
		if end < 0 {
			continue
		}
		arg := node.Value[open+1 : open+1+end]
		cmd := strings.Join(strings.Fields(masked[m[2]:m[3]]), " ")
		for _, loc := range userVarRe.FindAllStringSubmatchIndex(arg, -1) {
			// \$VAR inside double quotes is a literal dollar sign.
			if loc[0] > 0 && arg[loc[0]-1] == '\\' {
				continue
			}
			varName := arg[loc[2]:loc[3]]
			if seen[varName] {
				continue
			}
			seen[varName] = true
			findings = append(findings, finding.Finding{
				RuleID:   "GL002",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"user-controlled variable $%s is expanded into code evaluated by `%s` — quoting does not help, a crafted value runs as a command",
					varName, cmd,
				),
				File: file,
				Line: node.Line,
				Col:  node.Column,
			})
		}
	}
	return findings
}

// declarationWords take assignments as arguments and, like a plain
// assignment, don't word-split their values.
var declarationWords = map[string]bool{
	"export": true, "local": true, "readonly": true, "declare": true, "typeset": true,
}

// notWordSplit reports whether the unquoted variable reference at
// masked[dollarPos:end] sits where the shell does not word-split it, so a
// crafted value can't add arguments or commands there:
//   - the value of an assignment: X=$V, export X=$V, local X=$V, A=1 X=$V cmd
//   - inside [[ … ]]
//   - the word after case
//   - ${V+x} and ${V:+x}, which expand to x or nothing, never to the value
func notWordSplit(masked string, dollarPos, end int) bool {
	rest := masked[end:]
	if strings.HasPrefix(rest, "+") || strings.HasPrefix(rest, ":+") {
		return true
	}
	start := commandStart(masked, dollarPos)
	words := strings.Fields(masked[start:dollarPos])
	for len(words) > 0 && shellKeywords[words[0]] && !declarationWords[words[0]] {
		words = words[1:]
	}
	if len(words) > 0 && words[0] == "[[" && !containsWord(words, "]]") {
		return true
	}
	if len(words) == 1 && words[0] == "case" {
		return true
	}
	// The word holding the reference must be NAME=…, and every word before it
	// an assignment or a declaration builtin with its options.
	cur := ""
	if len(words) > 0 && dollarPos > 0 && !isShellSpace(masked[dollarPos-1]) {
		cur, words = words[len(words)-1], words[:len(words)-1]
	}
	if !assignmentRe.MatchString(cur) {
		return false
	}
	for i, w := range words {
		switch {
		case assignmentRe.MatchString(w):
		case declarationWords[w]:
		case strings.HasPrefix(w, "-") && i > 0 && declarationWords[words[0]]:
		default:
			return false
		}
	}
	return true
}

// commandStart returns where the simple command holding pos starts. The
// braces of a ${…} expansion don't separate commands, only those of a
// `{ …; }` group do (#976).
func commandStart(masked string, pos int) int {
	for i := pos - 1; i >= 0; i-- {
		switch c := masked[i]; c {
		case ';', '&', '|', '\n', '(', ')', '`':
			return i + 1
		case '{':
			if i == 0 || masked[i-1] != '$' {
				return i + 1
			}
		case '}':
			if i == 0 || strings.IndexByte(" \t;\n", masked[i-1]) >= 0 {
				return i + 1
			}
		}
	}
	return 0
}

func containsWord(words []string, w string) bool {
	for _, x := range words {
		if x == w {
			return true
		}
	}
	return false
}

// maskShellQuotes replaces the contents of single- and double-quoted shell
// strings with spaces. Variable references inside either quote type are safe
// from word splitting and should not be flagged; masking them makes the
// caller's regex only see genuinely unquoted occurrences.
//
// Backslash escapes outside quotes are also masked (two spaces replace the
// pair) because \$VAR is not a variable reference.
func maskShellQuotes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	maskShell(s, 0, &b, false)
	return b.String()
}

// maskShell writes the masked form of s from i on. In a command substitution
// (inSubst) it stops after the ) that closes it. A $( inside double quotes
// starts a new quoting context, as in the shell: in "$(jq --arg t "$TAG")"
// the inner "$TAG" is quoted on its own, and an unquoted $TAG in there would
// be split.
func maskShell(s string, i int, b *strings.Builder, inSubst bool) int {
	depth := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			b.WriteString("  ")
			i += 2
		case c == '\'':
			b.WriteByte('\'')
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(' ')
				i++
			}
			if i < len(s) {
				b.WriteByte('\'')
				i++
			}
		case c == '"':
			b.WriteByte('"')
			i++
			for i < len(s) && s[i] != '"' {
				switch {
				case s[i] == '\\' && i+1 < len(s):
					b.WriteString("  ")
					i += 2
				case strings.HasPrefix(s[i:], "$(") && !strings.HasPrefix(s[i:], "$(("):
					b.WriteString("$(")
					i = maskShell(s, i+2, b, true)
				default:
					b.WriteByte(' ')
					i++
				}
			}
			if i < len(s) {
				b.WriteByte('"')
				i++
			}
		case inSubst && c == '(':
			depth++
			b.WriteByte(c)
			i++
		case inSubst && c == ')':
			b.WriteByte(c)
			i++
			if depth == 0 {
				return i
			}
			depth--
		default:
			b.WriteByte(c)
			i++
		}
	}
	return i
}
