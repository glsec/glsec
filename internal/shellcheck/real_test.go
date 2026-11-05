// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package shellcheck

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

// requireEnv makes the tests below fail instead of skip without a ShellCheck.
// CI sets it on the Linux test job, which installs a pinned version (#1227).
const requireEnv = "GLSEC_REQUIRE_SHELLCHECK"

func realShellCheck(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("shellcheck")
	if err == nil {
		return bin
	}
	if os.Getenv(requireEnv) != "" {
		t.Fatalf("%s is set: %v", requireEnv, err)
	}
	t.Skipf("no ShellCheck in PATH; set %s to require it", requireEnv)
	return ""
}

func runReal(t *testing.T, bin, src string) []finding.Finding {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	got, err := Run(&doc, "test.yml", bin)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// These run the real program, so a change in its output or exit codes shows up
// here. Everything else in this package uses a fake.
func TestRealShellCheck(t *testing.T) {
	bin := realShellCheck(t)
	for _, tc := range []struct {
		name, src, rule string
		severity        finding.Severity
		line            int
	}{
		{"unquoted variable", "build:\n  script:\n    - echo $CI_COMMIT_REF_NAME\n", "SC2086", finding.Info, 3},
		{"later line of a block", "build:\n  script:\n    - |\n      echo first\n      echo $CI_COMMIT_REF_NAME\n", "SC2086", finding.Info, 5},
		{"before_script", "build:\n  before_script:\n    - echo $CI_COMMIT_REF_NAME\n  script:\n    - make\n", "SC2086", finding.Info, 3},
		{"warning", "build:\n  script:\n    - UNUSED=1\n", "SC2034", finding.Warn, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runReal(t, bin, tc.src)
			if len(got) != 1 {
				t.Fatalf("got %+v, want one finding", got)
			}
			f := got[0]
			if f.RuleID != tc.rule || f.Severity != tc.severity || f.Line != tc.line || f.Job != "build" {
				t.Errorf("got %+v, want %s, severity %s, line %d, job build", f, tc.rule, tc.severity, tc.line)
			}
			if f.Message == "" {
				t.Error("no message")
			}
		})
	}
}

func TestRealShellCheckSyntaxError(t *testing.T) {
	got := runReal(t, realShellCheck(t), "build:\n  script:\n    - if true; then\n")
	for _, f := range got {
		if f.Severity == finding.Error && strings.HasPrefix(f.RuleID, "SC1") {
			return
		}
	}
	t.Errorf("no SC1xxx error in %+v", got)
}

func TestRealShellCheckSilent(t *testing.T) {
	bin := realShellCheck(t)
	for _, tc := range []struct{ name, src string }{
		{"clean script", "build:\n  script:\n    - echo \"$CI_COMMIT_REF_NAME\"\n"},
		{"its own directive", "build:\n  script:\n    - |\n      # shellcheck disable=SC2086\n      echo $CI_COMMIT_REF_NAME\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runReal(t, bin, tc.src); len(got) != 0 {
				t.Errorf("got %+v", got)
			}
		})
	}
}
