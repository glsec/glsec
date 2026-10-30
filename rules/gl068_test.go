// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings068(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL068.Check(doc.Root, "test.yml")
}

func TestGL068_Flags(t *testing.T) {
	flagged := []string{
		"set -x",
		"set -euxo pipefail",
		"set -xe",
		"set -o xtrace",
		`[[ "$TRACE" ]] && set -x`,
	}
	for _, line := range flagged {
		f := findings068(t, "job:\n  script:\n    - '"+line+"'\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %q, got %d", line, len(f))
			continue
		}
		if f[0].RuleID != "GL068" || f[0].Severity != finding.Warn {
			t.Errorf("unexpected finding for %q: %+v", line, f[0])
		}
	}
}

func TestGL068_NotFlagged(t *testing.T) {
	clean := []string{
		"set -euo pipefail",          // no x
		"set +x",                     // disabling
		"set -o errexit",             // long form, not xtrace
		"set -x; ./build.sh; set +x", // net effect off — scoped on one line
		"echo set -x",                // not a set command
		"unset XTRACE",               // not `set`
		"# set -x",                   // comment
	}
	for _, line := range clean {
		if f := findings068(t, "job:\n  script:\n    - '"+line+"'\n"); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d: %+v", line, len(f), f)
		}
	}
}

func TestGL068_BeforeAndAfterScript(t *testing.T) {
	f := findings068(t, `
job:
  before_script:
    - set -x
  after_script:
    - set -o xtrace
  script:
    - echo hi
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (before+after script), got %d", len(f))
	}
}

func TestGL068_ShellInvocationFlags(t *testing.T) {
	flagged := []string{
		"bash -x ./deploy.sh",
		"bash -xe ./deploy.sh",
		"bash -ex ./deploy.sh",
		"bash -o xtrace ./deploy.sh",
		"sh -x -c \"echo hi\"",
		"sh -xc \"echo hi\"",
		"dash -x ./deploy.sh",
		"zsh -xe ./deploy.sh",
		"ksh -o xtrace ./deploy.sh",
		"sudo bash -x ./deploy.sh",
		"/usr/bin/bash -x ./deploy.sh",
		"bash -x",
	}
	for _, line := range flagged {
		f := findings068(t, "job:\n  script:\n    - '"+line+"'\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %q, got %d: %+v", line, len(f), f)
			continue
		}
		if f[0].RuleID != "GL068" || f[0].Severity != finding.Warn {
			t.Errorf("unexpected finding for %q: %+v", line, f[0])
		}
	}
}

func TestGL068_ShellInvocationNotFlagged(t *testing.T) {
	clean := []string{
		"bash script.sh -x",          // -x belongs to the script, not the shell
		"bash -c \"echo -x\"",        // -x inside the -c command string
		"bash -e ./deploy.sh",        // no x
		"bash +o xtrace ./deploy.sh", // disabling form
		"bash ./deploy.sh",
		"tar -xzf archive.tar.gz",
		"grep -x pattern file",
		"unzip -x archive.zip",
		"xargs -x echo",
		"echo bash -x",
		"docker run -x image",
		"# bash -x ./deploy.sh",
	}
	for _, line := range clean {
		if f := findings068(t, "job:\n  script:\n    - '"+line+"'\n"); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d: %+v", line, len(f), f)
		}
	}
}

func TestGL068_ShellOptsFlags(t *testing.T) {
	flagged := []string{
		"export SHELLOPTS=xtrace",
		"SHELLOPTS=xtrace",
		"SHELLOPTS=errexit:xtrace",
		"export SHELLOPTS=xtrace:errexit",
		"FOO=1 SHELLOPTS=xtrace ./deploy.sh",
	}
	for _, line := range flagged {
		f := findings068(t, "job:\n  script:\n    - '"+line+"'\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %q, got %d: %+v", line, len(f), f)
		}
	}
}

func TestGL068_ShellOptsNotFlagged(t *testing.T) {
	clean := []string{
		"export SHELLOPTS=errexit",
		"SHELLOPTS=",
		"echo SHELLOPTS=xtrace",
		"grep SHELLOPTS=xtrace file",
		"export SHELLOPTS",
	}
	for _, line := range clean {
		if f := findings068(t, "job:\n  script:\n    - '"+line+"'\n"); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d: %+v", line, len(f), f)
		}
	}
}

func TestGL068_VariablesShellOpts(t *testing.T) {
	f := findings068(t, `
variables:
  SHELLOPTS: xtrace
job:
  script:
    - echo hi
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for pipeline SHELLOPTS, got %d: %+v", len(f), f)
	}
	f = findings068(t, `
job:
  variables:
    SHELLOPTS: errexit:xtrace
  script:
    - echo hi
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for job SHELLOPTS, got %d: %+v", len(f), f)
	}
	f = findings068(t, `
job:
  variables:
    SHELLOPTS: errexit
  script:
    - echo hi
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for SHELLOPTS without xtrace, got %d: %+v", len(f), f)
	}
}

func TestGL068_InvocationBeforeAndAfterScript(t *testing.T) {
	f := findings068(t, `
job:
  before_script:
    - bash -o xtrace ./build.sh
  after_script:
    - zsh -xe ./cleanup.sh
  script:
    - echo hi
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (before+after script), got %d", len(f))
	}
}

// xtrace set inside a subshell ends with it (#997).
func TestGL068_SubshellXtrace(t *testing.T) {
	for line, want := range map[string]int{
		"( set -x ; cd /tmp && make )":       0,
		"(set -x; ./build.sh) && echo done":  0,
		"set -x":                             1,
		"( cd /tmp ) && set -x":              1,
		"echo \"$(set -x; date)\" && set -x": 1,
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - '"+line+"'\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL068.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("%s: got %d findings, want %d", line, got, want)
		}
	}
}

func TestGL068_MultiLineSubshellStillCounts(t *testing.T) {
	doc, err := parser.Parse([]byte("job:\n  script:\n    - |\n      (\n        set -x\n        ./deploy.sh\n      )\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(GL068.Check(doc.Root, "test.yml")); got != 1 {
		t.Errorf("got %d findings, want 1", got)
	}
}

// An escaped quote outside quotes doesn't open one, so the subshell after it
// is still blanked (#997).
func TestBlankSubshells_Escape(t *testing.T) {
	got := blankSubshells(`echo \"; (set -x; make)`)
	if strings.Contains(got, "set -x") {
		t.Errorf("subshell not blanked: %q", got)
	}
}
