// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings062(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL062.Check(doc.Root, "test.yml")
}

func TestGL062_Printenv(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - printenv
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL062" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL062_BareEnv(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for bare env, got %d", len(f))
	}
}

func TestGL062_UsrBinEnv(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - /usr/bin/env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for /usr/bin/env, got %d", len(f))
	}
}

func TestGL062_PrintenvWithVarNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - printenv DEPLOY_ENV
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for printenv VAR, got %d", len(f))
	}
}

func TestGL062_EnvSetVarNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - env FOO=bar ./run.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for env VAR=v cmd, got %d", len(f))
	}
}

func TestGL062_EnvRunCommandNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - env python script.py
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for env <command>, got %d", len(f))
	}
}

func TestGL062_PrintenvWithSeparator(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - printenv && echo done
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 'printenv &&', got %d", len(f))
	}
}

func TestGL062_EnvAfterSemicolon(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - cd /tmp; env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for '; env', got %d", len(f))
	}
}

func TestGL062_CommentNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - "# printenv would leak everything"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}

func TestGL062_EnvironmentWordNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - environment_setup.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for word containing env, got %d", len(f))
	}
}

// A dump on a later line of a block is reported on its line (#975).
func TestGL062_LaterLineOfABlock(t *testing.T) {
	doc, err := parser.Parse([]byte("debug:\n  script:\n    - |\n      echo start\n      env\n      printenv | sort\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := GL062.Check(doc.Root, "test.yml")
	if len(f) != 1 || f[0].Line != 5 {
		t.Fatalf("got %+v, want one finding on line 5", f)
	}
}

// A dump filtered to one non-secret variable is like printenv NAME; a broad
// filter is reported with its own message (#996).
func TestGL062_GrepFilter(t *testing.T) {
	for _, tc := range []struct {
		line, want string
	}{
		{"env | grep THREADS", ""},
		{"printenv | grep -E '^BUILD_JOBS='", ""},
		{"env | grep CI_REGISTRY", "filtered with grep"},
		{"env | grep ^CI", "filtered with grep"},
		{"env | grep -i token", "filtered with grep"},
		{"env | sort", "dumps every environment variable"},
		{"env | grep -E '^(CI|APP)_' > .env", ""},
		{"env > env.txt", ""},
	} {
		f := findings062(t, "job:\n  script:\n    - \""+tc.line+"\"\n")
		switch {
		case tc.want == "" && len(f) != 0:
			t.Errorf("%s: got %v, want no finding", tc.line, f)
		case tc.want != "" && (len(f) != 1 || !strings.Contains(f[0].Message, tc.want)):
			t.Errorf("%s: got %v, want a finding saying %q", tc.line, f, tc.want)
		}
	}
}

// Every other command that prints the whole environment is reported, while
// options that only set shell flags and per-variable filters stay clean
// (#1161).
func TestGL062_OtherDumpForms(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"set", true},
		{"set; echo done", true},
		{"make build && set", true},
		{"( set )", true},
		{"export", true},
		{"export -p", true},
		{"declare", true},
		{"declare -p", true},
		{"declare -x", true},
		{"declare -px", true},
		{"typeset -x", true},
		{"env -0", true},
		{"env --null", true},
		{"cat /proc/self/environ", true},
		{"gci env:", true},
		{"Get-ChildItem env:", true},
		{"Get-ChildItem Env: | Format-Table", true},
		{"Get-ChildItem -Path env:", true},
		{"dir env:", true},
		{"ls env:", true},
		{"Get-Item env:*", true},
		// Options and arguments that keep the command from dumping anything.
		{"set -e", false},
		{"set -u", false},
		{"set -euo pipefail", false},
		{"set -o pipefail", false},
		{"set +x", false},
		{"set --", false},
		{"export FOO=bar", false},
		{"export PATH=\"$PATH:/x\"", false},
		{"declare -r foo=bar", false},
		{"declare -a arr=(1 2)", false},
		{"declare -x FOO=bar", false},
		{"declare -p FOO", false},
		{"typeset -x FOO", false},
		{"env -i ls", false},
		{"cat .env", false},
		{"echo $env:PATH", false},
		{"Get-ChildItem env:PATH", false},
		{"Get-Item env:FOO", false},
		// Text inside quotes is not a command, even with separators in it.
		{`echo "hello; set; done"`, false},
		{`echo "hello; export -p"`, false},
		{`echo 'set'`, false},
		{`echo "hello; set > f"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			f := findings062(t, fmt.Sprintf("job:\n  script:\n    - %q\n", tc.line))
			switch {
			case tc.want && len(f) != 1:
				t.Fatalf("got %v, want one finding", f)
			case !tc.want && len(f) != 0:
				t.Fatalf("got %v, want no finding", f)
			}
		})
	}
}

func TestGrepPattern(t *testing.T) {
	for cmd, want := range map[string]string{
		"grep -e THREADS": "THREADS",
		"grep -i THREADS": "THREADS",
		"grep -v":         "",
		"sort":            "",
	} {
		if got, _ := grepPattern(cmd); got != want {
			t.Errorf("grepPattern(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// A dump after a case label is a command like any other; the label itself is
// not one (#1178).
func TestGL062_CaseArm(t *testing.T) {
	for _, tc := range []struct {
		arm  string
		want int
	}{
		{"debug) env ;;", 1},
		{"debug) set ;;", 1},
		{"debug) export -p ;;", 1},
		{"get|debug) printenv ;;", 1},
		{"set) env ;;", 1},
		{"debug) env | sort ;;", 1},
		{"debug) printenv VAR ;;", 0},
		{"debug) set -e ;;", 0},
		{"debug) env > vars.txt ;;", 0},
		{"set) do_it ;;", 0},
		{"env) do_it ;;", 0},
		{"debug) do_it ;;", 0},
	} {
		t.Run(tc.arm, func(t *testing.T) {
			src := "job:\n  script:\n    - |\n      case \"$1\" in\n        " + tc.arm + "\n      esac\n"
			f := findings062(t, src)
			if len(f) != tc.want {
				t.Fatalf("got %v, want %d findings", f, tc.want)
			}
			if tc.want == 1 && f[0].Line != 5 {
				t.Errorf("reported on line %d, want 5", f[0].Line)
			}
		})
	}
}

func TestBlankCaseLabels(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"debug) env", "       env"},
		{"a) env ;; b) set", "   env ;;    set"},
		{"get|debug) env", "get|       env"},
		{`case "$1" in debug) env ;; esac`, "                    env ;; esac"},
		{"( set )", "( set )"},
		{"(\n  make\n) > log", "(\n  make\n) > log"},
		{"echo $(date) done", "echo $(date) done"},
		{`echo "a) env"`, `echo "a) env"`},
		{"# a) env", "# a) env"},
		{"make # a) env", "make # a) env"},
		{`echo a\) env`, `echo a\) env`},
		{"no label", "no label"},
	} {
		if got := blankCaseLabels(tc.in); got != tc.want {
			t.Errorf("blankCaseLabels(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGL062_PowerShellPipelines(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{`gci env: | Select-String PATH`, 0},
		{`Get-ChildItem env: | Select-String -Pattern "PATH"`, 0},
		{`gci env: | Where-Object Name -eq PATH`, 0},
		{`gci env: | where Name -match 'PATH'`, 0},
		{`gci env: | Where-Object { $_.Name -match "album" }`, 0},
		{`gci env: | ? { $_.Name -eq "HOME" } | Format-Table -AutoSize`, 0},
		{`gci env: | Select-String TOKEN`, 1},
		{`gci env: | Select-String CI_`, 1},
		{`gci env: | Select-String -NotMatch PATH`, 1},
		{`gci env: | Sort-Object Name`, 1},
		{`gci env: | Where-Object Name -eq CI_JOB_TOKEN`, 1},
		{`gci env: | Where-Object Value -eq PATH`, 1},
		{`gci env: | Where-Object { $_.Name -match "album" -or $_.Value -match "album" }`, 1},
		{`gci env: | Where-Object { $_.Value -match "album" }`, 1},
		{`gci env: | Out-File env.txt`, 0},
		{`gci env: | Sort-Object Name | Set-Content env.txt`, 0},
		{`gci env: | Add-Content -Path env.txt`, 0},
		{`gci env: | Tee-Object env.txt`, 1},
	} {
		t.Run(tc.line, func(t *testing.T) {
			if got := checkRule(t, GL062, fmt.Sprintf("job:\n  script:\n    - %q\n", tc.line)); len(got) != tc.want {
				t.Errorf("got %d findings, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

func TestGL062_FilterNamedInMessage(t *testing.T) {
	got := checkRule(t, GL062, "job:\n  script:\n    - 'gci env: | Select-String TOKEN'\n")
	if len(got) != 1 || !strings.Contains(got[0].Message, `filtered with Select-String "TOKEN"`) {
		t.Errorf("got %v", got)
	}
}
