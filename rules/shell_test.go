// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"reflect"
	"testing"
)

func TestShellCommands(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   []shellCommand
	}{
		{"a && b || c; d | e & f", []shellCommand{{text: "a", line: 0}, {text: "b", line: 0}, {text: "c", line: 0}, {text: "d", line: 0}, {text: "e", line: 0}, {text: "f", line: 0}}},
		{"echo \"a | b; c\" && d", []shellCommand{{text: `echo "a | b; c"`, line: 0}, {text: "d", line: 0}}},
		{"echo 'x && y'", []shellCommand{{text: "echo 'x && y'", line: 0}}},
		{"cmd 2>&1 | tee log", []shellCommand{{text: "cmd 2>&1", line: 0}, {text: "tee log", line: 0}}},
		{"cmd &> log", []shellCommand{{text: "cmd &> log", line: 0}}},
		{"a \\\n  --flag\nb", []shellCommand{{text: "a    --flag", line: 0}, {text: "b", line: 2}}},
		{"# comment\na # trailing\nb", []shellCommand{{text: "a", line: 1}, {text: "b", line: 2}}},
		{"echo ${#ARR} $# x#y", []shellCommand{{text: "echo ${#ARR} $# x#y", line: 0}}},
		{"cat <<EOF > f\nsudo x | y\nEOF\nz", []shellCommand{{text: "cat <<EOF > f", line: 0}, {text: "z", line: 3}}},
		{"cat <<-'END'\n\tsudo x\n\tEND\nz", []shellCommand{{text: "cat <<-'END'", line: 0}, {text: "z", line: 3}}},
		{"cat <<< \"$x\" | y", []shellCommand{{text: `cat <<< "$x"`, line: 0}, {text: "y", line: 0}}},
		{"echo \"line1\nline2\" && b", []shellCommand{{text: "echo \"line1\nline2\"", line: 0}, {text: "b", line: 1}}},
	} {
		got := shellCommands(tc.script)
		for i := range got {
			got[i].piped, got[i].orElse, got[i].andThen = false, false, false
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("shellCommands(%q) = %+v, want %+v", tc.script, got, tc.want)
		}
	}
}

func TestShellCommandsPiped(t *testing.T) {
	got := shellCommands("a | b || c && d |& e")
	var piped []bool
	for _, c := range got {
		piped = append(piped, c.piped)
	}
	if want := []bool{true, false, false, true, false}; !reflect.DeepEqual(piped, want) {
		t.Errorf("piped = %v, want %v (%+v)", piped, want, got)
	}
}

func TestCommandWords(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []string
	}{
		{`curl -o "a b" url`, []string{"curl", "-o", "a b", "url"}},
		{`FOO=1 BAR="x y" curl url`, []string{"curl", "url"}},
		{`X=$(curl -sS url`, []string{"curl", "-sS", "url"}},
		{`if sudo -n true`, []string{"sudo", "-n", "true"}},
		{`env A=1 wget url`, []string{"wget", "url"}},
		{`( cd dir`, []string{"cd", "dir"}},
		{`A=1`, nil},
	} {
		if got := commandWords(tc.text); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("commandWords(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
	if got := withoutSudo([]string{"sudo", "-u", "nobody", "-E", "make"}); !reflect.DeepEqual(got, []string{"make"}) {
		t.Errorf("withoutSudo = %q", got)
	}
}

func TestShellCommandsSubstitutionInQuotes(t *testing.T) {
	got := shellCommands(`X="$(dotnet app.dll -version | cut -d':' -f2)" && echo "a | b"`)
	var texts []string
	for _, c := range got {
		texts = append(texts, c.text)
	}
	want := []string{`X="$(dotnet app.dll -version`, `cut -d':' -f2)"`, `echo "a | b"`}
	if !reflect.DeepEqual(texts, want) || !got[0].piped {
		t.Errorf("got %+v", got)
	}
	if got := shellCommands(`echo "$(( 1 | 2 ))"`); len(got) != 1 {
		t.Errorf("arithmetic expansion split: %+v", got)
	}
}

func TestShellCommands_Separators(t *testing.T) {
	got := shellCommands("a && b || c | d; e")
	want := []struct{ piped, orElse, andThen bool }{{andThen: true}, {orElse: true}, {piped: true}, {}, {}}
	if len(got) != len(want) {
		t.Fatalf("got %d commands, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].piped != w.piped || got[i].orElse != w.orElse || got[i].andThen != w.andThen {
			t.Errorf("command %q: got %+v, want %+v", got[i].text, got[i], w)
		}
	}
}
