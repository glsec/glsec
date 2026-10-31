// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package sensitivepaths

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot is two levels up from this test file (internal/sensitivepaths).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// runScript runs .github/scripts/sensitive-paths.sh with args and stdin, from
// the repo root, with dir prepended to PATH, and returns its output and exit code.
func runScript(t *testing.T, dir, stdin string, args ...string) (string, int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the script runs on the Linux runner")
	}
	for _, tool := range []string{"bash", "jq", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	cmd := exec.Command("bash", append([]string{".github/scripts/sensitive-paths.sh"}, args...)...) //nolint:gosec // G204: fixed script, arguments from the test table
	cmd.Dir = repoRoot(t)
	cmd.Stdin = strings.NewReader(stdin)
	if dir != "" {
		cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

type compareFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename,omitempty"`
	Patch            string `json:"patch,omitempty"`
}

// compareJSON is a compare API response with the given files.
func compareJSON(t *testing.T, files ...compareFile) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"files": files})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestFilter(t *testing.T) {
	in := strings.Join([]string{
		"rules/gl001.go",
		"hooks/hooks.json",
		".github/workflows/ci.yml",
		".github/scripts/sensitive-paths.sh",
		"mega-linter-plugin-glsec/glsec.megalinter-descriptor.yml",
		".pre-commit-hooks.yaml",
		".markdownlint-cli2.jsonc",
		".github/allowed_signers",
		".golangci.yml",
		"docs/rules/GL001.md",
		"sub/CLAUDE.md",
		"README.md",
	}, "\n") + "\n"
	want := strings.Join([]string{
		".github/allowed_signers",
		".github/scripts/sensitive-paths.sh",
		".github/workflows/ci.yml",
		".golangci.yml",
		".markdownlint-cli2.jsonc",
		".pre-commit-hooks.yaml",
		"hooks/hooks.json",
		"mega-linter-plugin-glsec/glsec.megalinter-descriptor.yml",
		"sub/CLAUDE.md",
	}, "\n") + "\n"
	got, code := runScript(t, "", in, "filter")
	if code != 0 || got != want {
		t.Errorf("filter = %q (exit %d), want %q", got, code, want)
	}
	if got, code := runScript(t, "", "README.md\ndocs/rules/GL001.md\n", "filter"); code != 0 || got != "" {
		t.Errorf("filter with no sensitive path = %q (exit %d), want empty, exit 0", got, code)
	}
}

// fakeGH writes a gh that answers `gh api repos/R/compare/B...<sha>` with the
// response stored for that sha, and fails for any other sha.
func fakeGH(t *testing.T, responses map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/usr/bin/env bash\nsha=${2##*...}\nf=\"" + dir + "/$sha.json\"\n[ -f \"$f\" ] || { echo \"not found\" >&2; exit 1; }\ncat \"$f\"\n"
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: an executable test helper
		t.Fatal(err)
	}
	for sha, body := range responses {
		if err := os.WriteFile(filepath.Join(dir, sha+".json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The label stays only when the pull request's diff on the sensitive paths is
// the same before and after the push (#1089); every doubt removes it.
func TestUnchanged(t *testing.T) {
	wf := compareFile{Filename: ".github/workflows/ci.yml", Patch: "@@ -1 +1 @@\n-a\n+b"}
	code := compareFile{Filename: "rules/gl001.go", Patch: "@@ -1 +1 @@\n-x\n+y"}
	tests := []struct {
		name          string
		before, after string
		want          int
	}{
		{"unchanged", compareJSON(t, wf, code), compareJSON(t, wf, code), 0},
		{"only other files changed", compareJSON(t, wf, code),
			compareJSON(t, wf, compareFile{Filename: "rules/gl001.go", Patch: "@@ -1 +1 @@\n-x\n+z"}, compareFile{Filename: "README.md", Patch: "+r"}), 0},
		{"no sensitive files at all", compareJSON(t, code), compareJSON(t, code, compareFile{Filename: "docs/x.md", Patch: "+d"}), 0},
		{"sensitive file changed", compareJSON(t, wf),
			compareJSON(t, compareFile{Filename: wf.Filename, Patch: "@@ -1 +1 @@\n-a\n+c"}), 1},
		{"sensitive file added", compareJSON(t, wf),
			compareJSON(t, wf, compareFile{Filename: "hooks/hooks.json", Patch: "+{}"}), 1},
		{"sensitive file added to a clean pull request", compareJSON(t, code),
			compareJSON(t, code, compareFile{Filename: "bin/glsec", Patch: "+x"}), 1},
		{"sensitive change reverted", compareJSON(t, wf, code), compareJSON(t, code), 1},
		{"renamed out of a sensitive path", compareJSON(t, wf),
			compareJSON(t, wf, compareFile{Filename: "docs/hooks.json", PreviousFilename: "hooks/hooks.json", Patch: ""}), 1},
		{"sensitive file without a patch", compareJSON(t, wf, compareFile{Filename: "assets/x.png"}),
			compareJSON(t, wf, compareFile{Filename: "bin/blob"}), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := fakeGH(t, map[string]string{"before": tt.before, "after": tt.after})
			out, code := runScript(t, dir, "", "unchanged", "o/r", "main", "before", "after")
			if code != tt.want {
				t.Errorf("exit %d, want %d; output:\n%s", code, tt.want, out)
			}
		})
	}

	t.Run("compare fails", func(t *testing.T) {
		dir := fakeGH(t, map[string]string{"after": compareJSON(t, wf)})
		if out, code := runScript(t, dir, "", "unchanged", "o/r", "main", "gone", "after"); code == 0 {
			t.Errorf("exit 0 for a before commit the API cannot compare; output:\n%s", out)
		}
	})
	t.Run("at the 300-file limit", func(t *testing.T) {
		many := make([]compareFile, 300)
		for i := range many {
			many[i] = compareFile{Filename: "rules/f" + string(rune('a'+i%26)) + ".go", Patch: "+"}
		}
		body := compareJSON(t, append(many[:299], wf)...)
		dir := fakeGH(t, map[string]string{"before": body, "after": body})
		if out, code := runScript(t, dir, "", "unchanged", "o/r", "main", "before", "after"); code == 0 {
			t.Errorf("exit 0 for a compare at the API's file limit; output:\n%s", out)
		}
	})
}
