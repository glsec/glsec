// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// A deploy step is often guarded in the script rather than in rules: (#1517
// follow-up): the job runs on every branch, but the push of latest sits in an
// if that tests for the default branch, or an early exit stops the script on
// every other ref. GL080 reads the YAML as written, so such a guard protects
// the step as a rules: guard does.

var (
	// shellIfRe matches one if/then[/else]/fi block whose condition is a test.
	// Nested blocks are not followed: the outer match ends at the first fi.
	shellIfRe = mustCompilePrefiltered(`(?s)\bif\s+(!?\s*(?:\[\[?|test\b)[^;\n]*?)\s*(?:;|\n)\s*then\b(.*?)(?:\belse\b(.*?))?\bfi\b`)
	// shellAndRe matches a test followed by && and the command it guards.
	shellAndRe = mustCompilePrefiltered(`((?:\[\[?|\btest\b)[^;\n&|]*?(?:\]\]?|$|\s))\s*&&\s*([^;\n|&]+)`)
	// shellExitGuardRe matches a test that ends the script: [ … ] || exit, or
	// [ … ] && exit, alone in its command.
	shellExitGuardRe = mustCompilePrefiltered(`((?:\[\[?|\btest\b)[^;\n&|]*?(?:\]\]?|\s))\s*(\|\||&&)\s*exit\b`)
	// shellIfExitRe matches if <test>; then exit …; fi.
	shellIfExitRe = mustCompilePrefiltered(`(?s)\bif\s+(!?\s*(?:\[\[?|test\b)[^;\n]*?)\s*(?:;|\n)\s*then\s+exit\b[^;\n]*\s*(?:;|\n)\s*fi\b`)
)

// refTest reports what a shell test says about the ref: +1 when it is true
// only on a protected or named ref (the default branch, a named branch, a tag,
// CI_COMMIT_REF_PROTECTED), -1 when it is true on every other ref, 0 when it
// says nothing glsec can read, such as a compound test.
func refTest(cond string) int {
	c := strings.TrimSpace(cond)
	sign := 1
	if strings.HasPrefix(c, "!") {
		sign = -1
		c = strings.TrimSpace(c[1:])
	}
	// [ and test split an unquoted operand into words, so an empty one
	// vanishes: [ -n $X ] is always true, and [ $X != main ] errors out, which
	// an if or && reads as false. [[ doesn't split.
	splits := true
	switch {
	case strings.HasPrefix(c, "[["):
		c = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(c, "[[")), "]]")
		splits = false
	case strings.HasPrefix(c, "["):
		c = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(c, "[")), "]")
	case strings.HasPrefix(c, "test"):
		c = strings.TrimPrefix(c, "test")
	default:
		return 0
	}
	f := strings.Fields(c)
	unquoted := false
	for _, w := range f {
		if splits && strings.HasPrefix(w, "$") {
			unquoted = true
		}
	}
	r := refTestFields(f, sign)
	if unquoted && (len(f) == 2 || r == -1) {
		return 0
	}
	return r
}

func refTestFields(f []string, sign int) int {
	for i, w := range f {
		w = strings.Trim(w, `"'`)
		if strings.HasPrefix(w, "${") && strings.HasSuffix(w, "}") {
			w = "$" + w[2:len(w)-1]
		}
		f[i] = w
	}
	switch len(f) {
	case 2:
		if f[1] != "$CI_COMMIT_TAG" {
			return 0
		}
		switch f[0] {
		case "-n":
			return sign
		case "-z":
			return -sign
		}
	case 3:
		a, op, b := f[0], f[1], f[2]
		var eq bool
		switch op {
		case "=", "==":
			eq = true
		case "!=":
		default:
			return 0
		}
		if b == "$CI_COMMIT_BRANCH" || b == "$CI_COMMIT_REF_PROTECTED" || b == "$CI_COMMIT_TAG" {
			a, b = b, a
		}
		// Not CI_COMMIT_REF_NAME: in a merge request pipeline it holds the
		// source branch's name, which a fork can call main.
		switch a {
		case "$CI_COMMIT_BRANCH":
			if b != "$CI_DEFAULT_BRANCH" && (b == "" || strings.ContainsAny(b, "$*?")) {
				return 0
			}
		case "$CI_COMMIT_REF_PROTECTED":
			switch b {
			case "true":
			case "false":
				eq = !eq
			default:
				return 0
			}
		case "$CI_COMMIT_TAG":
			if b != "" {
				return 0
			}
			eq = !eq
		default:
			return 0
		}
		if !eq {
			sign = -sign
		}
		return sign
	}
	return 0
}

// blankGuardedSteps returns text with the commands that only run on a
// protected or named ref replaced by spaces: the then-branch of an if whose
// test is true only there, the else-branch of one whose test is true
// everywhere else, and the command after such a test and &&.
func blankGuardedSteps(text string) string {
	if !strings.Contains(text, "CI_") {
		return text
	}
	code := blankShellComments(text)
	if len(code) != len(text) {
		return text
	}
	b := []byte(text)
	blank := func(start, end int) {
		for i := start; i < end; i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
	}
	for _, m := range shellIfRe.FindAllStringSubmatchIndex(code, -1) {
		// An elif or a nested if makes the branches more than glsec reads.
		if inner := code[m[3]:m[1]]; ifKeywordRe.MatchString(inner) {
			continue
		}
		switch refTest(code[m[2]:m[3]]) {
		case 1:
			blank(m[4], m[5])
		case -1:
			if m[6] >= 0 {
				blank(m[6], m[7])
			}
		}
	}
	for _, m := range shellAndRe.FindAllStringSubmatchIndex(code, -1) {
		// a || [ test ] && cmd runs cmd when a is true, whatever the test.
		if strings.HasSuffix(strings.TrimSpace(code[:m[2]]), "||") {
			continue
		}
		if refTest(code[m[2]:m[3]]) == 1 {
			blank(m[4], m[5])
		}
	}
	return string(b)
}

// exitGuardAt returns where a script line ends the script on every ref but
// a protected or named one, or -1: if [ "$CI_COMMIT_BRANCH" != main ]; then
// exit 0; fi, [ "$CI_COMMIT_BRANCH" = main ] || exit 0, or the && form. The
// guard must be a command of the script itself, not in a comment, a string,
// a subshell, a function, a loop or another if.
func exitGuardAt(text string) int {
	if !strings.Contains(text, "exit") || !strings.Contains(text, "CI_") {
		return -1
	}
	code := blankShellComments(text)
	if len(code) != len(text) {
		return -1
	}
	at := -1
	for _, m := range shellIfExitRe.FindAllStringSubmatchIndex(code, -1) {
		if refTest(code[m[2]:m[3]]) == -1 && topLevel(code, m[0]) {
			at = m[0]
			break
		}
	}
	for _, m := range shellExitGuardRe.FindAllStringSubmatchIndex(code, -1) {
		if at >= 0 && m[0] > at {
			break
		}
		t := refTest(code[m[2]:m[3]])
		op := code[m[4]:m[5]]
		if (op == "||" && t == 1 || op == "&&" && t == -1) && topLevel(code, m[0]) &&
			!strings.HasSuffix(strings.TrimSpace(code[:m[0]]), "||") && !strings.HasSuffix(strings.TrimSpace(code[:m[0]]), "&&") {
			at = m[0]
			break
		}
	}
	return at
}

// topLevel reports whether position pos of a shell script is outside quotes
// and outside any (, {, if, case or do block.
func topLevel(s string, pos int) bool {
	depth := 0
	var quote byte
	word := func(i int) string {
		j := i
		for j < len(s) && (s[j] >= 'a' && s[j] <= 'z') {
			j++
		}
		return s[i:j]
	}
	for i := 0; i < pos; i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '(' || c == '{':
			depth++
		case c == ')' || c == '}':
			depth--
		case c >= 'a' && c <= 'z' && (i == 0 || !isWordByte(s[i-1])):
			w := word(i)
			if i+len(w) < len(s) && isWordByte(s[i+len(w)]) {
				i += len(w) - 1
				continue
			}
			switch w {
			case "if", "case", "do":
				depth++
			case "fi", "esac", "done":
				depth--
			}
			i += len(w) - 1
		}
	}
	return quote == 0 && depth == 0
}

func isWordByte(c byte) bool {
	return c == '_' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// ifKeywordRe matches an if or elif keyword.
var ifKeywordRe = mustCompilePrefiltered(`(?:^|[\s;&|(])(?:el)?if\s`)

// withEntryVariables returns job with the variables: of the rules: entry
// merged over its own, as GitLab does when that entry matches.
func withEntryVariables(job, entry *yaml.Node) *yaml.Node {
	ev := parser.FindKey(entry, "variables")
	if ev == nil || ev.Kind != yaml.MappingNode || len(ev.Content) == 0 {
		return job
	}
	merged := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if jv := parser.FindKey(job, "variables"); jv != nil && jv.Kind == yaml.MappingNode {
		merged.Content = append(merged.Content, jv.Content...)
	}
	merged = mergeMappings(merged, ev)
	out := *job
	out.Content = make([]*yaml.Node, 0, len(job.Content)+2)
	replaced := false
	for i := 0; i+1 < len(job.Content); i += 2 {
		if job.Content[i].Value == "variables" {
			out.Content = append(out.Content, job.Content[i], merged)
			replaced = true
			continue
		}
		out.Content = append(out.Content, job.Content[i], job.Content[i+1])
	}
	if !replaced {
		out.Content = append(out.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "variables"}, merged)
	}
	return &out
}

// localRsync reports an rsync or scp that copies between paths of the job's
// working tree: no host:path, host::module or rsync:// operand, no -e/--rsh,
// no variable or command substitution that could hold a remote, and a
// relative destination.
func localRsync(w []string) bool {
	last := ""
	for _, a := range w[1:] {
		if a == "-e" || strings.HasPrefix(a, "--rsh") || strings.ContainsAny(a, "$:`") {
			return false
		}
		if !strings.HasPrefix(a, "-") {
			last = a
		}
	}
	// On a shell runner an absolute or home destination is the host itself,
	// such as a web root.
	return !strings.HasPrefix(last, "/") && !strings.HasPrefix(last, "~")
}
