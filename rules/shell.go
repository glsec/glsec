// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// shellCommand is one simple command of a script item: the text between
// unquoted separators (newline, ;, |, ||, &&, &).
type shellCommand struct {
	text string
	// line is the index of the item line the command starts on, for
	// parser.ScalarContentLine.
	line int
	// piped is set when the command's output goes into the next command
	// through a single |.
	piped bool
	// orElse and andThen are set when || or && follows the command.
	orElse, andThen bool
	// parent is the command whose sh -c script this one comes from, or "".
	parent string
}

// heredocRe matches a here-document operator and its delimiter, quoted or not.
var heredocRe = regexp.MustCompile(`^<<-?\s*(?:'([^']+)'|"([^"]+)"|\\?([A-Za-z_][A-Za-z0-9_.-]*))`)

// inArithmetic reports whether text ends inside (( … )) or $(( … )), where <<
// is a shift and not a here-document.
func inArithmetic(text string) bool {
	return strings.Count(text, "((") > strings.Count(text, "))")
}

// shellCommands splits a script item into simple commands. Quotes and
// backslash escapes are respected, a backslash-newline continues the command,
// comments are dropped, and the bodies of here-documents are skipped, so text
// that is only data never reads as a command. A body a local shell reads as
// its script is split into commands instead, after the line that opens it
// (#1216): on another machine, as with ssh, it stays data. So is the script of
// a local sh -c, after all other commands so that a pipeline stays in order
// (#1218).
func shellCommands(script string) []shellCommand {
	var cmds []shellCommand
	var cur strings.Builder
	line, start := 0, -1
	var heredocs []string
	heredocCmd := 0 // index in cmds of the command that opens them
	emit := func(piped bool) {
		if t := strings.TrimSpace(cur.String()); t != "" {
			cmds = append(cmds, shellCommand{text: t, line: start, piped: piped})
		}
		cur.Reset()
		start = -1
	}
	add := func(s string) {
		if start < 0 && strings.TrimSpace(s) != "" {
			start = line
		}
		cur.WriteString(s)
	}
	var quote byte
	// A $( inside double quotes opens a new, unquoted context until its ):
	// "$(a | b)" runs a pipeline. substs holds the open parentheses of each.
	var substs []int
	for i := 0; i < len(script); i++ {
		c := script[i]
		if quote == '"' && c == '$' && strings.HasPrefix(script[i:], "$(") && !strings.HasPrefix(script[i:], "$((") {
			cur.WriteString("$(")
			i++
			substs = append(substs, 0)
			quote = 0
			continue
		}
		if quote != 0 {
			if c == '\n' {
				line++
			}
			if c == '\\' && quote == '"' && i+1 < len(script) {
				cur.WriteByte(c)
				i++
				if script[i] == '\n' {
					line++
				}
				cur.WriteByte(script[i])
				continue
			}
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		if n := len(substs); n > 0 {
			switch c {
			case '(':
				substs[n-1]++
			case ')':
				if substs[n-1] == 0 {
					substs = substs[:n-1]
					cur.WriteByte(c)
					quote = '"'
					continue
				}
				substs[n-1]--
			}
		}
		switch {
		case c == '\\' && i+1 < len(script):
			if script[i+1] == '\n' {
				line++
				cur.WriteByte(' ')
			} else {
				add(script[i : i+2])
			}
			i++
		case c == '\'' || c == '"':
			add(string(c))
			quote = c
		case c == '#' && (cur.Len() == 0 || isShellSpace(script[i-1])):
			for i+1 < len(script) && script[i+1] != '\n' {
				i++
			}
		case c == '<' && strings.HasPrefix(script[i:], "<<") && !strings.HasPrefix(script[i:], "<<<") && !inArithmetic(cur.String()):
			if m := heredocRe.FindStringSubmatch(script[i:]); m != nil {
				if len(heredocs) == 0 {
					heredocCmd = len(cmds)
				}
				heredocs = append(heredocs, m[1]+m[2]+m[3])
				add(m[0])
				i += len(m[0]) - 1
			} else {
				add(string(c))
			}
		case c == '\n':
			emit(false)
			line++
			runs := len(heredocs) == 1 && shellReadsHeredoc(cmds, heredocCmd)
			for _, delim := range heredocs {
				start, first := i+1, line
				i = skipHeredoc(script, i, delim, &line)
				if runs {
					cmds = append(cmds, heredocCommands(script[start:i], delim, first)...)
				}
			}
			heredocs = nil
		case c == ';':
			emit(false)
		case c == '&' && (i > 0 && (script[i-1] == '>' || script[i-1] == '<') || i+1 < len(script) && script[i+1] == '>'):
			add(string(c)) // a redirection such as 2>&1 or &>file
		case c == '|' && i > 0 && script[i-1] == '>':
			add(string(c)) // >| forces a redirect
		case c == '|' || c == '&':
			if i+1 < len(script) && script[i+1] == c {
				i++
				n := len(cmds)
				emit(false)
				if len(cmds) > n {
					cmds[n].orElse, cmds[n].andThen = c == '|', c == '&'
				}
			} else {
				emit(c == '|')
			}
		default:
			add(string(c))
		}
	}
	emit(false)
	if mayRunShellC(script) {
		for _, cmd := range cmds {
			if inner, ok := shellCText(cmd.text); ok {
				for _, c := range shellCommands(inner) {
					c.line += cmd.line
					if c.parent == "" {
						c.parent = cmd.text
					}
					cmds = append(cmds, c)
				}
			}
		}
	}
	return cmds
}

// mayRunShellC cheaply rules out scripts without a shell's -c.
func mayRunShellC(script string) bool {
	return strings.Contains(script, "sh ") && strings.Contains(script, "c ")
}

// shellCText returns the script of a command that runs a local shell with -c.
func shellCText(text string) (string, bool) {
	if !strings.Contains(text, "sh ") {
		return "", false
	}
	words := commandWords(text)
	if !posixShells[commandName(words)] {
		return "", false
	}
	i := shellCArg(words[1:])
	if i < 0 {
		return "", false
	}
	return words[i+1], true
}

// skipHeredoc moves past a here-document body that starts after the newline
// at i, up to and including its delimiter line, and returns the new index of
// the last consumed byte.
func skipHeredoc(script string, i int, delim string, line *int) int {
	for j := i + 1; j <= len(script); {
		end := strings.IndexByte(script[j:], '\n')
		if end < 0 {
			end = len(script) - j
		}
		body := script[j : j+end]
		*line++
		if strings.TrimSpace(body) == delim {
			return j + end
		}
		j += end + 1
	}
	return len(script)
}

// heredocCommands splits a here-document body, up to its delimiter line, into
// commands. first is the item line the body starts on.
func heredocCommands(body, delim string, first int) []shellCommand {
	if i := strings.LastIndexByte(body, '\n'); strings.TrimSpace(body[i+1:]) == delim {
		body = body[:i+1]
	}
	cmds := shellCommands(body)
	for i := range cmds {
		cmds[i].line += first
	}
	return cmds
}

// shellReadsHeredoc reports whether the here-document opened by cmds[at] is the
// script of a local shell: bash <<EOF or cat <<EOF | bash.
func shellReadsHeredoc(cmds []shellCommand, at int) bool {
	text, _, _ := strings.Cut(cmds[at].text, "<<")
	return readsScriptFromStdin(commandWords(text)) ||
		cmds[at].piped && at+1 < len(cmds) && readsScriptFromStdin(commandWords(cmds[at+1].text))
}

// readsScriptFromStdin reports a shell that takes its script from stdin: it
// has neither -c nor a script file, or it has -s.
func readsScriptFromStdin(words []string) bool {
	if !posixShells[commandName(words)] {
		return false
	}
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "-o" || w == "+o" || w == "-O" || w == "+O":
			i++
		case strings.HasPrefix(w, "--") && w != "--" || strings.HasPrefix(w, "+"):
		case !strings.HasPrefix(w, "-") || w == "--":
			return false
		case strings.Contains(w, "c"):
			return false
		case strings.Contains(w, "s"):
			return true
		}
	}
	return true
}

// blankShellComments replaces every shell comment in s with spaces, keeping
// the length and the newlines so regex offsets still point into the original
// text. A # starts a comment where a word can start, outside quotes; a quote
// inside a comment therefore cannot open a quoted region that hides the rest
// of a block from quote masking.
func blankShellComments(s string) string {
	b := []byte(s)
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' && i+1 < len(s) {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\\' && i+1 < len(s):
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || strings.IndexByte(" \t\n;|&()", s[i-1]) >= 0):
			for ; i < len(s) && s[i] != '\n'; i++ {
				b[i] = ' '
			}
			if i < len(s) {
				i-- // the newline is not part of the comment
			}
		}
	}
	return string(b)
}

func isShellSpace(c byte) bool { return c == ' ' || c == '\t' }

// blankCaseLabels replaces each case label in a script with spaces, keeping
// offsets and lines, so the command after it starts a command: `debug) env ;;`
// reads as `       env ;;` (#1178). A label is a ) with no ( open before it,
// outside quotes and comments. Its alternatives belong to it, so the whole of
// `set|get)` is blanked, not only `get)` (#1176).
func blankCaseLabels(script string) string {
	if !strings.Contains(script, ")") {
		return script
	}
	masked := maskShellQuotes(script)
	b := []byte(script)
	depth, start := 0, 0
	for i := 0; i < len(masked); i++ {
		switch c := masked[i]; {
		case c == '#' && (i == 0 || isShellSpace(masked[i-1]) || masked[i-1] == '\n'):
			for i+1 < len(masked) && masked[i+1] != '\n' {
				i++
			}
		case c == '\n' || c == ';' || c == '&':
			start = i + 1
		case c == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case c == ')':
			for j := start; j <= i; j++ {
				b[j] = ' '
			}
			start = i + 1
		}
	}
	return string(b)
}

// shellKeywords are reserved words and wrappers that come before the command
// a simple command runs.
var shellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "{": true, "(": true,
	"time": true, "exec": true, "command": true, "nohup": true,
	"export": true, "local": true, "readonly": true, "declare": true,
}

var assignmentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// commandWords returns the words of the program a simple command runs, with
// quotes removed; see unwrapCommand.
func commandWords(text string) []string {
	return unwrapCommand(shellWords(text))
}

// unwrapCommand drops what comes before the program a command runs: keywords,
// variable assignments, env and wrappers such as sudo or timeout, however they
// nest. For `VAR=$(cmd …` the command inside the substitution is used.
func unwrapCommand(words []string) []string {
	return unwrapUntil(words, "")
}

// unwrapUntil is unwrapCommand stopping at the wrapper named stop, for a rule
// about that wrapper itself.
func unwrapUntil(words []string, stop string) []string {
	for len(words) > 0 {
		w := words[0]
		name := commandName(words)
		wrapper, wrapped := commandWrappers[name]
		switch {
		case name == stop:
			return words
		case w == "env":
			words = skipEnvOptions(words[1:])
		case wrapped:
			words = wrapper.skip(words[1:])
		case shellKeywords[w]:
			words = words[1:]
		case strings.HasPrefix(w, "$("):
			words = closeSubstitution(append([]string{w[2:]}, words[1:]...))
		case strings.HasPrefix(w, "("):
			words[0] = w[1:]
		case assignmentRe.MatchString(w):
			value := w[strings.IndexByte(w, '=')+1:]
			if strings.HasPrefix(value, "$(") {
				words = closeSubstitution(append([]string{value[2:]}, words[1:]...))
				continue
			}
			words = words[1:]
		default:
			if w == "" {
				words = words[1:]
				continue
			}
			return words
		}
	}
	return nil
}

// closeSubstitution cuts the words of a $( … ) at the ) that closes it, so the
// words after it don't read as the inner command's arguments: in
// `$(curl -sSL URL) -o x`, -o x belongs to the outer command (#1281).
func closeSubstitution(words []string) []string {
	depth := 0
	for i, w := range words {
		for j := 0; j < len(w); j++ {
			switch w[j] {
			case '(':
				depth++
			case ')':
				if depth > 0 {
					depth--
					continue
				}
				out := append([]string{}, words[:i]...)
				if w[:j] != "" {
					out = append(out, w[:j])
				}
				return out
			}
		}
	}
	return words
}

// commandWrapper describes a program that runs the command it is given.
type commandWrapper struct {
	// values are the short options that take a value, long the long ones.
	values string
	long   []string
	// args counts the arguments before the command: timeout's duration.
	args int
}

var commandWrappers = map[string]commandWrapper{
	"sudo": {values: "CDghpRrtTUu", long: []string{
		"--user", "--group", "--chdir", "--prompt", "--chroot", "--role", "--type",
		"--command-timeout", "--other-user", "--close-from", "--host",
	}},
	"doas":    {values: "auC"},
	"timeout": {values: "ks", long: []string{"--kill-after", "--signal"}, args: 1},
	"nice":    {values: "n", long: []string{"--adjustment"}},
	"ionice":  {values: "cnpPu", long: []string{"--class", "--classdata", "--pid", "--pgid", "--uid"}},
	"stdbuf":  {values: "ioe", long: []string{"--input", "--output", "--error"}},
	"nohup":   {},
	"time":    {values: "fo", long: []string{"--format", "--output"}},
	"exec":    {values: "a"},
}

// skip drops the wrapper's options and arguments from the words after its
// name. In a cluster such as -Hu node the value belongs to the last letter; in
// -unode it is attached.
func (c commandWrapper) skip(words []string) []string {
	for len(words) > 0 && strings.HasPrefix(words[0], "-") {
		option := words[0]
		words = words[1:]
		if option == "--" {
			break
		}
		takesValue := false
		if strings.HasPrefix(option, "--") {
			takesValue = slices.Contains(c.long, option)
		} else if i := strings.IndexAny(option[1:], c.values); i >= 0 {
			takesValue = i == len(option)-2
		}
		if takesValue {
			words = words[min(1, len(words)):]
		}
	}
	return words[min(c.args, len(words)):]
}

// wrapperWordRe finds a line that may hold a wrapper, so unwrappedLine leaves
// all others alone without parsing them.
var wrapperWordRe = mustCompilePrefiltered(`(?:^|[\s;&|(/])(?:` +
	strings.Join(slices.Sorted(maps.Keys(commandWrappers)), "|") + `)\s`)

// unwrappedLine removes the wrappers in front of a line's commands, for rules
// that find the command position with a regular expression. Separators, line
// breaks and quotes stay as they are. A wrapper inside $( … ) stays too:
// captured output is what such a rule tells apart.
func unwrappedLine(line string) string {
	if !wrapperWordRe.MatchString(line) {
		return line
	}
	var b strings.Builder
	pos := 0
	for _, cmd := range shellCommands(line) {
		i := strings.Index(line[pos:], cmd.text)
		if i < 0 {
			continue
		}
		b.WriteString(line[pos : pos+i])
		b.WriteString(unwrappedText(cmd.text))
		pos += i + len(cmd.text)
	}
	b.WriteString(line[pos:])
	return b.String()
}

// unwrappedText returns a simple command from its program on, as written.
func unwrappedText(text string) string {
	words := shellWords(text)
	total := len(words)
	rest := unwrapUntil(words, "env")
	if len(rest) == 0 || len(rest) == total {
		return text
	}
	i := skipWords(text, total-len(rest))
	if strings.ContainsAny(text[:i], "$`") {
		return text
	}
	return text[i:]
}

// skipWords returns the index in text of the word after the first n.
func skipWords(text string, n int) int {
	i := 0
	for ; n > 0; n-- {
		var quote byte
		for ; i < len(text) && (quote != 0 || !isShellSpace(text[i]) && text[i] != '\n'); i++ {
			switch c := text[i]; {
			case quote != 0 && c == quote:
				quote = 0
			case c == '\\' && quote != '\'':
				i++
			case quote == 0 && (c == '\'' || c == '"'):
				quote = c
			}
		}
		for i < len(text) && (isShellSpace(text[i]) || text[i] == '\n') {
			i++
		}
	}
	return min(i, len(text))
}

// envValueOptions are env's options that take the next word as their value.
var envValueOptions = map[string]bool{"-u": true, "--unset": true, "-C": true, "--chdir": true}

// skipEnvOptions drops env's own options from the words after env, so the
// assignments and the command it runs follow (#1082): flags such as -i, -0,
// -v and -, options with a value (-u NAME, --unset=NAME, -C DIR) and --.
// -S/--split-string splits its value into the words of the command.
func skipEnvOptions(words []string) []string {
	for len(words) > 0 && strings.HasPrefix(words[0], "-") {
		w := words[0]
		switch {
		case w == "--":
			return words[1:]
		case w == "-S" || w == "--split-string":
			if len(words) < 2 {
				return nil
			}
			return append(shellWords(words[1]), words[2:]...)
		case strings.HasPrefix(w, "--split-string="):
			return append(shellWords(strings.TrimPrefix(w, "--split-string=")), words[1:]...)
		case envValueOptions[w]:
			words = words[min(2, len(words)):]
		default:
			words = words[1:]
		}
	}
	return words
}

// commandName returns the base name of the program a command runs:
// "/usr/bin/curl" and "curl" are both "curl".
func commandName(words []string) string {
	if len(words) == 0 {
		return ""
	}
	return strings.TrimSuffix(path.Base(words[0]), ".exe")
}

// shellWords splits a command into words, removing quotes and backslashes.
// Inside double quotes a backslash only escapes $, `, ", \ and a newline.
func shellWords(text string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' && i+1 < len(text) && strings.IndexByte("$`\"\\\n", text[i+1]) >= 0 {
				i++
				cur.WriteByte(text[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == '\\' && i+1 < len(text):
			i++
			cur.WriteByte(text[i])
			inWord = true
		case isShellSpace(c) || c == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// maskSingleQuoted blanks out single-quoted text, where nothing is expanded.
func maskSingleQuoted(s string) string {
	b := []byte(s)
	in := false
	for i, c := range b {
		switch {
		case c == '\'':
			in = !in
		case in:
			b[i] = ' '
		}
	}
	return string(b)
}

// logicalLine is one line of a script item, with backslash continuations
// joined.
type logicalLine struct {
	text string
	line int // index of the item line it starts on
}

// logicalLines splits a script item into lines, joining a line that ends in a
// backslash with the next one.
func logicalLines(script string) []logicalLine {
	var out []logicalLine
	var cur strings.Builder
	start := 0
	for i, l := range strings.Split(script, "\n") {
		if cur.Len() == 0 {
			start = i
		}
		if (len(l)-len(strings.TrimRight(l, "\\")))%2 == 1 {
			cur.WriteString(strings.TrimSuffix(l, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(l)
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, logicalLine{text: t, line: start})
		}
		cur.Reset()
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, logicalLine{text: t, line: start})
	}
	return out
}

// gitArgs returns the words of a git command from its subcommand on, past the
// global options (-C dir, -c key=value, --git-dir dir or --git-dir=dir, the
// same for --work-tree, and flags such as --no-pager), and whether those
// options point at another repository (-C, --git-dir, --work-tree).
func gitArgs(words []string) (args []string, otherRepo bool) {
	if commandName(words) != "git" {
		return nil, false
	}
	args = words[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		a := args[0]
		if a == "-C" || strings.HasPrefix(a, "--git-dir") || strings.HasPrefix(a, "--work-tree") {
			otherRepo = true
		}
		args = args[1:]
		if (a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree") && len(args) > 0 {
			args = args[1:]
		}
	}
	return args, otherRepo
}

// posixShells run the script after -c, or read one from stdin.
var posixShells = map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true}
