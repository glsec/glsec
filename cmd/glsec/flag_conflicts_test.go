// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// Contradictory flag combinations fail or warn instead of being resolved
// silently (#903).
func TestRun_ContradictoryFlagsFail(t *testing.T) {
	files := map[string]string{"error.yml": errorPipeline, "base.json": `{"findings": []}`}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--generate-ignore", "--new-only", "error.yml"}, "--generate-ignore writes a new baseline"},
		{[]string{"--generate-ignore", "--baseline", "base.json", "error.yml"}, "--generate-ignore writes a new baseline"},
		{[]string{"--no-ignores", "--new-only", "error.yml"}, "--no-ignores reports every finding"},
		{[]string{"--no-ignores", "--baseline", "base.json", "error.yml"}, "--no-ignores reports every finding"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			code, stdout, stderr := runCLI(t, files, tc.args...)
			if code != 2 || !strings.Contains(stderr, "error: "+tc.want) {
				t.Errorf("exit %d, want 2 with %q; stderr:\n%s", code, tc.want, stderr)
			}
			if stdout != "" {
				t.Errorf("a report was written:\n%s", stdout)
			}
			if _, err := os.Stat(".glsec-ignore"); err == nil {
				t.Error(".glsec-ignore was written")
			}
		})
	}
}

func TestRun_FlagsWithoutEffectWarn(t *testing.T) {
	files := map[string]string{"error.yml": errorPipeline, "warn.yml": warnPipeline}

	t.Run("--strict --no-exit-codes", func(t *testing.T) {
		code, _, stderr := runCLI(t, files, "--strict", "--no-exit-codes", "warn.yml")
		if code != 0 || !strings.Contains(stderr, "warning: strict has no effect with no-exit-codes") {
			t.Errorf("exit %d, want 0 with the warning:\n%s", code, stderr)
		}
	})
	t.Run("strict and no-exit-codes in .glsec.yml", func(t *testing.T) {
		f := map[string]string{"warn.yml": warnPipeline, ".glsec.yml": "strict: true\nno-exit-codes: true\n"}
		code, _, stderr := runCLI(t, f, "warn.yml")
		if code != 0 || !strings.Contains(stderr, "warning: strict has no effect with no-exit-codes") {
			t.Errorf("exit %d, want 0 with the warning:\n%s", code, stderr)
		}
	})
	t.Run("--generate-ignore --format json", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, files, "--generate-ignore", "--format", "json", "error.yml")
		if code != 0 || !strings.Contains(stderr, "warning: --format has no effect with --generate-ignore") {
			t.Errorf("exit %d, want 0 with the warning:\n%s", code, stderr)
		}
		if stdout != "" {
			t.Errorf("a report was printed:\n%s", stdout)
		}
		if data, err := os.ReadFile(".glsec-ignore"); err != nil || !strings.Contains(string(data), "GL001") {
			t.Errorf(".glsec-ignore not written as usual: %v\n%s", err, data)
		}
	})
	t.Run("--clear-cache with a file and flags", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, files, "--clear-cache", "--strict", "--format", "json", "error.yml")
		if code != 0 || !strings.Contains(stderr, "warning: --clear-cache only empties the cache and exits; ignoring --format, --strict, file arguments") {
			t.Errorf("exit %d, want 0 with the warning:\n%s", code, stderr)
		}
		if !strings.Contains(stderr, "cache cleared") || stdout != "" {
			t.Errorf("not just a cleared cache: stdout %q, stderr:\n%s", stdout, stderr)
		}
	})
	t.Run("no warning on their own", func(t *testing.T) {
		for _, args := range [][]string{
			{"--clear-cache"},
			{"--strict", "warn.yml"},
			{"--no-exit-codes", "error.yml"},
			{"--generate-ignore", "error.yml"},
			{"--format", "json", "error.yml"},
		} {
			_, _, stderr := runCLI(t, files, args...)
			if strings.Contains(stderr, "has no effect") || strings.Contains(stderr, "ignoring --") {
				t.Errorf("%v warns:\n%s", args, stderr)
			}
		}
	})
}
