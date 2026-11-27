// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"sort"
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
	shellIfRe = mustCompilePrefiltered(`(?s)\bif\s+(!?\s*(?:\[\[?|test\b|echo\b)[^;\n]*?)\s*(?:;|\n)\s*then\b(.*?)(?:\belse\b(.*?))?\bfi\b`)
	// shellAndRe matches a test followed by && and the command it guards.
	shellAndRe = mustCompilePrefiltered(`((?:\[\[?|\btest\b)[^;\n&|]*?(?:\]\]?|$|\s))\s*&&\s*([^;\n|&]+)`)
	// shellExitGuardRe matches a test that ends the script: [ … ] || exit, or
	// [ … ] && exit, alone in its command.
	// The exit may sit in a brace group after other commands:
	// [ -n "$X" ] || { echo skip; exit 0; }.
	shellExitGuardRe = mustCompilePrefiltered(`((?:\[\[?|\btest\b)[^;\n&|]*?(?:\]\]?|\s))\s*(\|\||&&)\s*(?:\{\s*(?:[^{}\n;]*;\s*)*)?exit\b`)
	// shellGrepExitRe matches echo "$VAR" | grep … || exit, or the && form.
	shellGrepExitRe = mustCompilePrefiltered(`(\becho\s[^;\n|&]*\|\s*grep\s[^;\n|&]*?)\s*(\|\||&&)\s*(?:\{\s*(?:[^{}\n;]*;\s*)*)?exit\b`)
	// grepTestRe splits echo "$VAR" | grep [-flags] 'pattern'.
	grepTestRe = mustCompilePrefiltered(`^echo\s+("?)\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?("?)\s*\|\s*grep\s+((?:-[A-Za-z]+\s+)*)(?:-e\s+)?(?:'([^']*)'|"([^"]*)")\s*$`)
	// shellIfExitRe matches if <test>; then exit …; fi.
	shellIfExitRe = mustCompilePrefiltered(`(?s)\bif\s+(!?\s*(?:\[\[?|test\b|echo\b)[^;\n]*?)\s*(?:;|\n)\s*then\s+exit\b[^;\n]*\s*(?:;|\n)\s*fi\b`)
)

// refTest reports what a shell test says about the ref: +1 when it is true
// only on a protected or named ref (the default branch, a named branch, a tag,
// CI_COMMIT_REF_PROTECTED), -1 when it is true on every other ref, 0 when it
// says nothing glsec can read, such as a compound test. flags are variables
// that only protected refs set (protectedFlags); a test that one is set reads
// like a test of CI_COMMIT_TAG.
func refTest(cond string, flags map[string]bool) int {
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
	case strings.HasPrefix(c, "echo"):
		return grepRefTest(c, sign, flags)
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
	r := refTestFields(f, sign, flags)
	if unquoted && (len(f) == 2 || r == -1) {
		return 0
	}
	return r
}

func refTestFields(f []string, sign int, flags map[string]bool) int {
	for i, w := range f {
		w = strings.Trim(w, `"'`)
		if strings.HasPrefix(w, "${") && strings.HasSuffix(w, "}") {
			w = "$" + w[2:len(w)-1]
		}
		f[i] = w
	}
	flag := func(w string) bool {
		return strings.HasPrefix(w, "$") && flags[w[1:]]
	}
	switch len(f) {
	case 2:
		if f[1] != "$CI_COMMIT_TAG" && !flag(f[1]) {
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
		if b == "$CI_COMMIT_BRANCH" || b == "$CI_COMMIT_REF_PROTECTED" || b == "$CI_COMMIT_TAG" || flag(b) {
			a, b = b, a
		}
		if flag(a) {
			// Elsewhere the flag is empty: = "" holds there, = true doesn't.
			if strings.Contains(b, "$") {
				return 0
			}
			if b == "" {
				eq = !eq
			}
			if !eq {
				sign = -sign
			}
			return sign
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

// grepRefTest reads echo "$CI_COMMIT_TAG" | grep -qE 'pattern' (#1527).
// Outside a tag pipeline the variable is empty, echo prints one empty line,
// and grep selects it only if the pattern matches the empty string (with -v,
// only if it doesn't). The test is then false on every other ref (+1) or true
// on every other ref (-1). Only CI_COMMIT_TAG and protected-only flags are
// read: a branch name is never empty.
func grepRefTest(c string, sign int, flags map[string]bool) int {
	m := grepTestRe.FindStringSubmatch(c)
	if m == nil || m[1] != m[3] || m[2] != "CI_COMMIT_TAG" && !flags[m[2]] {
		return 0
	}
	invert, whole, fold := false, false, false
	for _, opt := range strings.Fields(m[4]) {
		for _, o := range opt[1:] {
			switch o {
			case 'v':
				invert = !invert
			case 'x':
				whole = true
			case 'i':
				fold = true
			case 'q', 'E', 'o', 's', 'P', 'e':
			default:
				return 0
			}
		}
	}
	pattern := m[5] + m[6]
	// Inside double quotes the shell expands a variable first.
	if strings.Contains(strings.TrimSuffix(m[6], "$"), "$") {
		return 0
	}
	if whole {
		pattern = "^(?:" + pattern + ")$"
	}
	if fold {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return 0
	}
	if re.MatchString("") != invert {
		return -sign
	}
	return sign
}

// blankGuardedSteps returns text with the commands that only run on a
// protected or named ref replaced by spaces: the then-branch of an if whose
// test is true only there, the else-branch of one whose test is true
// everywhere else, and the command after such a test and &&.
func blankGuardedSteps(text string, flags map[string]bool) string {
	if !strings.Contains(text, "CI_") && len(flags) == 0 {
		return text
	}
	// blankShellComments keeps every offset.
	code := blankShellComments(text)
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
		switch refTest(code[m[2]:m[3]], flags) {
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
		if refTest(code[m[2]:m[3]], flags) == 1 {
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
func exitGuardAt(text string, flags map[string]bool) int {
	if !strings.Contains(text, "exit") || !strings.Contains(text, "CI_") && len(flags) == 0 {
		return -1
	}
	// blankShellComments keeps every offset.
	code := blankShellComments(text)
	at := -1
	for _, m := range shellIfExitRe.FindAllStringSubmatchIndex(code, -1) {
		if refTest(code[m[2]:m[3]], flags) == -1 && topLevel(code, m[0]) {
			at = m[0]
			break
		}
	}
	guards := shellExitGuardRe.FindAllStringSubmatchIndex(code, -1)
	if strings.Contains(code, "grep") {
		guards = append(guards, shellGrepExitRe.FindAllStringSubmatchIndex(code, -1)...)
		sort.Slice(guards, func(i, j int) bool { return guards[i][0] < guards[j][0] })
	}
	for _, m := range guards {
		if at >= 0 && m[0] > at {
			break
		}
		t := refTest(code[m[2]:m[3]], flags)
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
	depth, parens := 0, 0
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
		case c == '(':
			parens++
		case c == ')':
			// A case pattern's ) has no ( to close.
			if parens > 0 {
				parens--
			}
		case c == '{':
			depth++
		case c == '}':
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
	return quote == 0 && depth == 0 && parens == 0
}

func isWordByte(c byte) bool {
	return c == '_' || c == '-' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// protectedFlags returns the variables that only rules: entries restricted to
// protected refs set (#1524), such as PUSH_TAGS: latest on the default-branch
// entry: neither another entry nor the job's or the file's variables: set
// them, and no script in the file assigns them or writes them to a dotenv
// report. On every other ref they are empty, so [ -n "$PUSH_TAGS" ] || exit 0
// guards like a ref test. A pipeline variable from a manual run can still set
// one, but whoever starts a pipeline on their own branch can also edit the
// YAML, which GL080 doesn't model; a fork's merge request can do neither.
func protectedFlags(in *Inheritance, job, globalVars *yaml.Node) map[string]bool {
	rules := parser.FindKey(job, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return nil
	}
	var flags map[string]bool
	var unsafe []string
	for _, item := range rules.Content {
		v := parser.FindKey(item, "variables")
		if v == nil || v.Kind != yaml.MappingNode {
			continue
		}
		if w := parser.FindKey(item, "when"); w != nil && w.Value == "never" {
			continue
		}
		cond := parser.FindKey(item, "if")
		protected := cond != nil && cond.Kind == yaml.ScalarNode && ifRestrictsToProtected(cond.Value)
		for i := 0; i+1 < len(v.Content); i += 2 {
			name := v.Content[i].Value
			if !protected || strings.HasPrefix(name, "CI_") || strings.HasPrefix(name, "GITLAB_") {
				unsafe = append(unsafe, name)
				continue
			}
			if flags == nil {
				flags = map[string]bool{}
			}
			flags[name] = true
		}
	}
	if flags == nil {
		return nil
	}
	for _, name := range unsafe {
		delete(flags, name)
	}
	for _, vars := range []*yaml.Node{parser.FindKey(job, "variables"), globalVars} {
		for name := range literalVariables(vars) {
			delete(flags, name)
		}
	}
	for name := range flags {
		if in.scriptAssigns(name) {
			delete(flags, name)
		}
	}
	return flags
}

// scriptAssigns reports whether a script line of any job or template in the
// file assigns name or writes it to a file, as a dotenv report does
// (NAME=value, export NAME=, ${NAME:=value}).
func (in *Inheritance) scriptAssigns(name string) bool {
	for _, job := range in.jobs {
		if job.Kind != yaml.MappingNode {
			continue
		}
		for _, line := range CollectJobScriptLines(job) {
			v := line.Value
			for i := strings.Index(v, name); i >= 0; {
				end := i + len(name)
				if (i == 0 || !isWordByte(v[i-1])) && (strings.HasPrefix(v[end:], "=") || strings.HasPrefix(v[end:], ":=")) {
					return true
				}
				next := strings.Index(v[end:], name)
				if next < 0 {
					break
				}
				i = end + next
			}
		}
	}
	return false
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
