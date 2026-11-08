// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/rule"
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
		{"env -i PATH=/usr/bin curl -fsSLo x u", []string{"curl", "-fsSLo", "x", "u"}},
		{"env --ignore-environment -0 -v make", []string{"make"}},
		{"env - A=1 make", []string{"make"}},
		{"env -u HOME -C /tmp make", []string{"make"}},
		{"env --unset=HOME --chdir /tmp make", []string{"make"}},
		{"env -- -weird", []string{"-weird"}},
		{`env -S "curl -fsSL u" -o x`, []string{"curl", "-fsSL", "u", "-o", "x"}},
		{`env --split-string="make all"`, []string{"make", "all"}},
		{"sudo env -i apt-get install x", []string{"apt-get", "install", "x"}},
		{"env -u", nil},
		{"env -S", nil},
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

func TestUnwrapCommandSudo(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"sudo apt-get install x", "apt-get install x"},
		{"sudo -u app -E make", "make"},
		{"sudo -g wheel -C 3 ls", "ls"},
		{"apt-get install x", "apt-get install x"},
		{"sudo", ""},
		{"sudo env -i PATH=/usr/bin curl x", "curl x"},
		{"sudo -u app HOME=/srv make", "make"},
		{"sudo -E env make", "make"},
		{"sudo -Hu node npm ci", "npm ci"},
		{"sudo -iu node npm ci", "npm ci"},
		{"sudo -su node npm ci", "npm ci"},
		{"sudo -HE npm ci", "npm ci"},
		{"sudo -uuser npm ci", "npm ci"},
		{"sudo -E -- npm ci", "npm ci"},
		{"sudo --user node npm ci", "npm ci"},
		{"sudo --user=node npm ci", "npm ci"},
		{"sudo -T 30 npm ci", "npm ci"},
		{"sudo -R /chroot npm ci", "npm ci"},
		{"sudo -- npm ci", "npm ci"},
		{"doas -u node npm ci", "npm ci"},
		{"doas -n npm ci", "npm ci"},
		{"doas -C config npm ci", "npm ci"},
		{"doas -unode npm ci", "npm ci"},
		{"doas -a bsdauth npm ci", "npm ci"},
		{"doas -nu node npm ci", "npm ci"},
	} {
		got := strings.Join(unwrapCommand(strings.Fields(tc.in)), " ")
		if got != tc.want {
			t.Errorf("unwrapCommand(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnwrapCommandSudoValueOptions(t *testing.T) {
	for _, option := range []string{"-C", "-D", "-g", "-h", "-p", "-R", "-r", "-t", "-T", "-U", "-u", "--user", "--group", "--chdir", "--prompt", "--chroot", "--role", "--type", "--command-timeout", "--other-user", "--close-from", "--host"} {
		t.Run(option, func(t *testing.T) {
			got := strings.Join(unwrapCommand([]string{"sudo", option, "value", "npm", "ci"}), " ")
			if got != "npm ci" {
				t.Errorf("got %q, want npm ci", got)
			}
		})
	}
}

func TestUnwrapCommandSudoEmptyPrompt(t *testing.T) {
	got := strings.Join(unwrapCommand(shellWords(`sudo -p '' npm ci`)), " ")
	if got != "npm ci" {
		t.Fatalf("got %q, want npm ci", got)
	}
}

func TestUnwrapCommandWrappers(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"timeout 600 npm ci", "npm ci"},
		{"timeout -k 5 -s KILL 60 npm ci", "npm ci"},
		{"timeout -k5 --signal=KILL 60 npm ci", "npm ci"},
		{"timeout --signal KILL --preserve-status --foreground -v 1m npm ci", "npm ci"},
		{"timeout 60", ""},
		{"nice npm ci", "npm ci"},
		{"nice -n 10 npm ci", "npm ci"},
		{"nice -10 npm ci", "npm ci"},
		{"nice --adjustment 10 npm ci", "npm ci"},
		{"ionice -c 2 -n 7 -t npm ci", "npm ci"},
		{"ionice --class 2 npm ci", "npm ci"},
		{"stdbuf -oL npm ci", "npm ci"},
		{"stdbuf -i 0 -oL -e0 npm ci", "npm ci"},
		{"stdbuf --output=L npm ci", "npm ci"},
		{"stdbuf --output L npm ci", "npm ci"},
		{"nohup npm ci", "npm ci"},
		{"time npm ci", "npm ci"},
		{"time -p npm ci", "npm ci"},
		{"time -- npm ci", "npm ci"},
		{"/usr/bin/time -v -o out.txt npm ci", "npm ci"},
		{"exec npm ci", "npm ci"},
		{"exec -a name npm ci", "npm ci"},
		{"exec -cl npm ci", "npm ci"},
		{"nice -n 10 timeout 60 sudo -Hu node env A=1 npm ci", "npm ci"},
		{"timeout 60 FOO=1 npm ci", "npm ci"},
		{"/usr/bin/sudo npm ci", "npm ci"},
		{"command -v npm", "-v npm"},
	} {
		got := strings.Join(unwrapCommand(strings.Fields(tc.in)), " ")
		if got != tc.want {
			t.Errorf("unwrapCommand(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnwrappedLine(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"npm ci", "npm ci"},
		{"timeout 60 env", "env"},
		{"sudo env", "env"},
		{"cd x && nice -n 10 renovate --autodiscover; ls", "cd x && renovate --autodiscover; ls"},
		{`timeout 60 claude -p "a; b" | tee log`, `claude -p "a; b" | tee log`},
		{`sudo -p '' env`, "env"},
		{`sudo -p "a b" env`, "env"},
		{`sudo -p a\ b env`, "env"},
		{"a\ntimeout 60 env\nb", "a\nenv\nb"},
		{"X=$(sudo env)", "X=$(sudo env)"},
		{"$(timeout 5 env)", "$(timeout 5 env)"},
		{"sudo -v", "sudo -v"},
		{"timeout 60 sudo", "timeout 60 sudo"},
		{"echo timeout 60 env", "echo timeout 60 env"},
		{"sudo apt install env", "apt install env"},
		{"sudo a \\\nb", "sudo a \\\nb"},
	} {
		if got := unwrappedLine(tc.in); got != tc.want {
			t.Errorf("unwrappedLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReadsScriptFromStdin(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"bash", true},
		{"/bin/sh", true},
		{"sudo -u node bash", true},
		{"timeout 60 bash -e", true},
		{"bash -ex", true},
		{"bash -s", true},
		{"bash -s -- a b", true},
		{"bash -es arg", true},
		{"bash -o pipefail", true},
		{"bash +x", true},
		{"bash --norc", true},
		{"bash -c true", false},
		{"bash -ec true", false},
		{"bash script.sh", false},
		{"bash -e script.sh", false},
		{"bash -- script.sh", false},
		{"cat", false},
		{"python3", false},
		{"ssh host bash", false},
		{"", false},
	} {
		if got := readsScriptFromStdin(commandWords(tc.in)); got != tc.want {
			t.Errorf("readsScriptFromStdin(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestShellCommandsArithmeticShift(t *testing.T) {
	var got []string
	for _, c := range shellCommands("echo $((a<<b))\ncurl x\nb\n((c<<d))\nwget y\ncat <<EOF\nnot a command\nEOF\nls") {
		got = append(got, c.text)
	}
	want := []string{"echo $((a<<b))", "curl x", "b", "((c<<d))", "wget y", "cat <<EOF", "ls"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLogicalLinesEscapedBackslash(t *testing.T) {
	got := logicalLines("echo a\\\\\nls\necho b\\\nc\n")
	if len(got) != 3 || got[0].text != `echo a\\` || got[1].text != "ls" || got[2].text != "echo b c" {
		t.Errorf("got %+v", got)
	}
}

func TestShellWordsBackslashInDoubleQuotes(t *testing.T) {
	got := shellWords(`"C:\path" "\$a" "\"b" "\\c" "\` + "`" + `d" 'e\f' g\h`)
	want := []string{`C:\path`, "$a", `"b`, `\c`, "`d", `e\f`, "gh"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
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

func TestWrappedCommandsReachRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rule   rule.Rule
		script string
		want   int
	}{
		{"GL021 sudo", GL021, `sudo echo "$API_TOKEN"`, 1},
		{"GL021 timeout", GL021, `timeout 5 echo "$API_TOKEN"`, 1},
		{"GL021 redirect", GL021, `timeout 5 echo "$API_TOKEN" > file`, 0},
		{"GL050 timeout", GL050, "timeout 60 apt-get update && timeout 60 sudo apt-get update", 1},
		{"GL050 after dropped", GL050, "sudo -Hu node sudo apt-get update", 1},
		{"GL050 substitution of a dropped sudo", GL050, "sudo -u a b $(sudo -u a c)", 0},
		{"GL062 timeout", GL062, "timeout 60 env", 1},
		{"GL062 sudo", GL062, "sudo printenv", 1},
		{"GL062 sudo procfs", GL062, "sudo cat /proc/1/environ", 1},
		{"GL062 filtered", GL062, "sudo env | grep THREADS", 0},
		{"GL062 captured", GL062, "X=$(sudo env)", 0},
		{"GL062 package", GL062, "sudo apt install env", 0},
		{"GL050 local heredoc", GL050, "bash <<EOF\nsudo apt-get update\nEOF", 1},
		{"GL050 piped heredoc", GL050, "cat <<EOF | bash\nsudo apt-get update\nEOF", 1},
		{"GL050 ssh heredoc", GL050, "ssh h <<EOF\nsudo apt-get update\nEOF", 0},
		{"GL050 written heredoc", GL050, "cat > f <<EOF\nsudo apt-get update\nEOF", 0},
		{"GL050 stdin of a script", GL050, "bash run.sh <<EOF\nsudo apt-get update\nEOF", 0},
		{"GL062 local heredoc", GL062, "sudo sh -s <<'EOF'\nprintenv\nEOF", 1},
		{"GL062 ssh heredoc", GL062, "ssh h <<'EOF'\nprintenv\nEOF", 0},
		{"GL050 sh -c", GL050, "bash -c 'sudo apt-get update'", 1},
		{"GL050 sh -ec behind a wrapper", GL050, `timeout 60 sh -ec "sudo apt-get update"`, 1},
		{"GL050 ssh", GL050, "ssh h 'sudo apt-get update'", 0},
		{"GL050 quoted text", GL050, `echo "bash -c sudo"`, 0},
		{"GL062 sh -c", GL062, "bash -c 'printenv'", 1},
		{"GL062 sudo in sh -c", GL062, "bash -c 'sudo printenv'", 1},
		{"GL062 ssh", GL062, "ssh h 'printenv'", 0},
		{"GL020 sh -c", GL020, `sh -c "wget https://x.example/a.tgz"`, 1},
		{"GL068 timeout", GL068, "timeout 60 bash -x build.sh", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := fmt.Sprintf("job:\n  script:\n    - %q\n", tc.script)
			if got := checkRule(t, tc.rule, src); len(got) != tc.want {
				t.Errorf("got %d findings, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}
