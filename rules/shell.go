// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
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
}

// heredocRe matches a here-document operator and its delimiter, quoted or not.
var heredocRe = regexp.MustCompile(`^<<-?\s*(?:'([^']+)'|"([^"]+)"|\\?([A-Za-z_][A-Za-z0-9_]*))`)

// shellCommands splits a script item into simple commands. Quotes and
// backslash escapes are respected, a backslash-newline continues the command,
// comments are dropped, and the bodies of here-documents are skipped, so text
// that is only data never reads as a command.
func shellCommands(script string) []shellCommand {
	var cmds []shellCommand
	var cur strings.Builder
	line, start := 0, -1
	var heredocs []string
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
		case c == '<' && strings.HasPrefix(script[i:], "<<") && !strings.HasPrefix(script[i:], "<<<"):
			if m := heredocRe.FindStringSubmatch(script[i:]); m != nil {
				heredocs = append(heredocs, m[1]+m[2]+m[3])
				add(m[0])
				i += len(m[0]) - 1
			} else {
				add(string(c))
			}
		case c == '\n':
			emit(false)
			line++
			for _, delim := range heredocs {
				i = skipHeredoc(script, i, delim, &line)
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
	return cmds
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

func isShellSpace(c byte) bool { return c == ' ' || c == '\t' }

// shellKeywords are reserved words and wrappers that come before the command
// a simple command runs.
var shellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "{": true, "(": true,
	"time": true, "exec": true, "command": true, "nohup": true,
	"export": true, "local": true, "readonly": true, "declare": true,
}

var assignmentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// commandWords returns the words of a simple command from the command name
// on, with quotes removed: leading keywords, variable assignments and env are
// dropped, and for `VAR=$(cmd …` the command inside the substitution is used.
func commandWords(text string) []string {
	words := shellWords(text)
	for len(words) > 0 {
		w := words[0]
		switch {
		case w == "env":
			words = skipEnvOptions(words[1:])
		case shellKeywords[w]:
			words = words[1:]
		case strings.HasPrefix(w, "$("):
			words[0] = w[2:]
		case strings.HasPrefix(w, "("):
			words[0] = w[1:]
		case assignmentRe.MatchString(w):
			value := w[strings.IndexByte(w, '=')+1:]
			if strings.HasPrefix(value, "$(") {
				words[0] = value[2:]
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

// withoutSudo drops a leading sudo and its options, so the words start at the
// command sudo runs.
func withoutSudo(words []string) []string {
	if commandName(words) != "sudo" {
		return words
	}
	words = words[1:]
	for len(words) > 0 && strings.HasPrefix(words[0], "-") {
		takesValue := words[0] == "-u" || words[0] == "-g" || words[0] == "-C" || words[0] == "-D"
		words = words[1:]
		if takesValue && len(words) > 0 {
			words = words[1:]
		}
	}
	// sudo VAR=value cmd, sudo env -i VAR=value cmd (#1082).
	for len(words) > 0 {
		switch {
		case words[0] == "env":
			words = skipEnvOptions(words[1:])
		case assignmentRe.MatchString(words[0]):
			words = words[1:]
		default:
			return words
		}
	}
	return words
}

// shellWords splits a command into words, removing quotes and backslashes.
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
			} else if c == '\\' && quote == '"' && i+1 < len(text) {
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
		if strings.HasSuffix(l, "\\") {
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
