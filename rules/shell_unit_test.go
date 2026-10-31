// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"reflect"
	"strings"
	"testing"
)

// Unit tests for the shell helpers most rules build on (#1079). The rule tests
// cover them too, but a bug here breaks many rules at once; these point at it.

func TestShellWords(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"curl -fsSL https://x", []string{"curl", "-fsSL", "https://x"}},
		{"  a\t b  ", []string{"a", "b"}},
		{`echo "a b" 'c d'`, []string{"echo", "a b", "c d"}},
		{`echo "a \"q\" b"`, []string{"echo", `a "q" b`}},
		{`echo 'a \n b'`, []string{"echo", `a \n b`}},
		{`echo a\ b`, []string{"echo", "a b"}},
		{`x="$HOME"y`, []string{"x=$HOMEy"}},
		{`echo ""`, []string{"echo", ""}},
		{"", nil},
	} {
		if got := shellWords(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("shellWords(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCommandWords_Prefixes(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"curl -fsSL x", []string{"curl", "-fsSL", "x"}},
		{"if curl x", []string{"curl", "x"}},
		{"export A=1", nil},
		{"A=1 B=2 make all", []string{"make", "all"}},
		{"env make", []string{"make"}},
		{"V=$(curl -fsSL x", []string{"curl", "-fsSL", "x"}},
		{"$(git rev-parse HEAD", []string{"git", "rev-parse", "HEAD"}},
		{"(cd dir", []string{"cd", "dir"}},
		{"A=1", nil},
		{"", nil},
	} {
		if got := commandWords(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("commandWords(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCommandName(t *testing.T) {
	for _, tc := range []struct {
		words []string
		want  string
	}{
		{[]string{"curl", "x"}, "curl"},
		{[]string{"/usr/bin/curl"}, "curl"},
		{[]string{`C:\tools\curl.exe`}, `C:\tools\curl`},
		{[]string{"./bin/glsec.exe"}, "glsec"},
		{nil, ""},
	} {
		if got := commandName(tc.words); got != tc.want {
			t.Errorf("commandName(%q) = %q, want %q", tc.words, got, tc.want)
		}
	}
}

func TestWithoutSudo(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"sudo apt-get install x", "apt-get install x"},
		{"sudo -u app -E make", "make"},
		{"sudo -g wheel -C 3 ls", "ls"},
		{"apt-get install x", "apt-get install x"},
		{"sudo", ""},
	} {
		got := strings.Join(withoutSudo(strings.Fields(tc.in)), " ")
		if got != tc.want {
			t.Errorf("withoutSudo(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLogicalLines(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []logicalLine
	}{
		{"a", []logicalLine{{"a", 0}}},
		{"a\nb\n", []logicalLine{{"a", 0}, {"b", 1}}},
		{"a \\\n  --x \\\n  --y\nb", []logicalLine{{"a    --x    --y", 0}, {"b", 3}}},
		{"\n\n  a  \n", []logicalLine{{"a", 2}}},
		{"a \\", []logicalLine{{"a", 0}}},
		{"", nil},
	} {
		if got := logicalLines(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("logicalLines(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

func TestSkipHeredoc(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		delim  string
		rest   string // what follows the heredoc
		lines  int    // lines consumed, the delimiter line included
	}{
		{"plain", "cat <<EOF\nbody $X\nEOF\nnext", "EOF", "\nnext", 2},
		{"indented delimiter", "cat <<-EOF\n\tbody\n\tEOF\nnext", "EOF", "\nnext", 2},
		{"empty body", "cat <<EOF\nEOF\nnext", "EOF", "\nnext", 1},
		{"delimiter as a word in the body", "cat <<EOF\nEOF is near\nEOF\nnext", "EOF", "\nnext", 2},
		{"unterminated", "cat <<EOF\nbody\nmore", "EOF", "", 2},
	} {
		start := strings.IndexByte(tc.script, '\n')
		line := 0
		end := skipHeredoc(tc.script, start, tc.delim, &line)
		if end > len(tc.script) {
			t.Fatalf("%s: index %d past the script", tc.name, end)
		}
		if rest := tc.script[end:]; rest != tc.rest || line != tc.lines {
			t.Errorf("%s: rest %q after %d lines, want %q after %d", tc.name, rest, line, tc.rest, tc.lines)
		}
	}
}

func TestMaskSingleQuoted(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"echo 'a | b' | c", "echo '     ' | c"},
		{`echo "a | b"`, `echo "a | b"`},
		{"echo 'unterminated | x", "echo '" + strings.Repeat(" ", 16)},
		{"", ""},
	} {
		got := maskSingleQuoted(tc.in)
		if got != tc.want {
			t.Errorf("maskSingleQuoted(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if len(got) != len(tc.in) {
			t.Errorf("maskSingleQuoted(%q) changed the length", tc.in)
		}
	}
}

func TestIsShellSpace(t *testing.T) {
	for c, want := range map[byte]bool{' ': true, '\t': true, '\n': false, 'a': false, 0: false} {
		if got := isShellSpace(c); got != want {
			t.Errorf("isShellSpace(%q) = %v, want %v", c, got, want)
		}
	}
}
