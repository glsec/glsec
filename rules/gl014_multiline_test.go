// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func TestGL014_BlockScalarDumpForms(t *testing.T) {
	for _, style := range []struct{ name, script string }{
		{"scalar", "  script: |\n    echo start\n    %s\n"},
		{"list item", "  script:\n    - |\n      echo start\n      %s\n"},
	} {
		t.Run(style.name, func(t *testing.T) {
			for _, command := range []string{
				"env > vars.txt", // Existing alternative: the whitespace boundary already matched.
				"set > vars.txt",
				"export > vars.txt",
				"declare -p > vars.txt",
				"typeset -x > vars.txt",
				"gci env: > vars.txt",
				"Get-ChildItem Env: | Format-Table > vars.txt",
				"Get-Item env:* | tee vars.txt",
			} {
				t.Run(command, func(t *testing.T) {
					src := "build:\n" + fmt.Sprintf(style.script, command) + "  artifacts:\n    paths: [vars.txt]\n"
					f := findings014(t, src)
					if len(f) != 1 {
						t.Fatalf("expected one finding for a dump after a newline, got %v", f)
					}
					if f[0].RuleID != "GL014" || f[0].Severity != finding.Warn || f[0].Job != "build" {
						t.Errorf("unexpected finding: %+v", f[0])
					}
				})
			}
			for _, command := range []string{
				"set -e > vars.txt",
				"export FOO=bar > vars.txt",
				"declare -a arr > vars.txt",
				"Get-ChildItem env:PATH > vars.txt",
				"Get-ChildItem env: | Select-String PATH > vars.txt",
				`echo "hello; set > vars.txt"`,
			} {
				t.Run(command, func(t *testing.T) {
					src := "build:\n" + fmt.Sprintf(style.script, command) + "  artifacts:\n    paths: [vars.txt]\n"
					if f := findings014(t, src); len(f) != 0 {
						t.Fatalf("expected no finding for an option, variable or quoted text, got %v", f)
					}
				})
			}
		})
	}
}
