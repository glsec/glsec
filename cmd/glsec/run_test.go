package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/rules"
)

const (
	cleanPipeline = `workflow:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
test:
  image: alpine:3.20.3@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a
  script:
    - echo "running tests"
`
	// GL001 (error) and GL053 (warn).
	errorPipeline = `job:
  image: node:latest
  script:
    - echo hi
`
	// GL024 (warn) only.
	warnPipeline = `workflow:
  rules:
    - if: $CI_COMMIT_BRANCH
job:
  image: alpine:3.20.3@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a
  script:
    - curl -fsSL https://gitlab.com/x | tee out
`
	brokenPipeline = "job: [unclosed\n"
)

// runCLI writes files into a fresh directory, runs the CLI there and returns
// its exit code and output. The cache goes to a temp dir and colour is off, so
// runs don't leak into each other or into the user's cache.
func runCLI(t *testing.T, files map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")

	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun_ExitCodes(t *testing.T) {
	files := map[string]string{
		"clean.yml":  cleanPipeline,
		"error.yml":  errorPipeline,
		"warn.yml":   warnPipeline,
		"broken.yml": brokenPipeline,
	}
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"clean file", []string{"clean.yml"}, 0},
		{"error finding", []string{"error.yml"}, 1},
		{"warn only", []string{"warn.yml"}, 0},
		{"warn only with --strict", []string{"--strict", "warn.yml"}, 1},
		{"error with --no-exit-codes", []string{"--no-exit-codes", "error.yml"}, 0},
		{"--no-exit-codes overrides --strict", []string{"--strict", "--no-exit-codes", "warn.yml"}, 0},
		{"unparsable YAML", []string{"broken.yml"}, 2},
		{"unparsable file next to a clean one", []string{"clean.yml", "broken.yml"}, 2},
		{"missing file", []string{"missing.yml"}, 2},
		{"unknown flag", []string{"--bogus", "clean.yml"}, 2},
		{"unknown format", []string{"--format", "xml", "clean.yml"}, 2},
		{"invalid --gitlab-version", []string{"--gitlab-version", "abc", "clean.yml"}, 2},
		{"help", []string{"-h"}, 0},
		{"excluded error file", []string{"--exclude", "error.yml", "clean.yml", "error.yml"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, files, tt.args...)
			if code != tt.want {
				t.Fatalf("run(%v) = %d, want %d; stderr:\n%s", tt.args, code, tt.want, stderr)
			}
		})
	}
}

func TestRun_DefaultFileIsGitlabCI(t *testing.T) {
	code, stdout, _ := runCLI(t, map[string]string{".gitlab-ci.yml": errorPipeline}, "--format", "json")
	if code != 1 || !strings.Contains(stdout, "GL001") {
		t.Fatalf("expected GL001 from the default .gitlab-ci.yml, got exit %d:\n%s", code, stdout)
	}
}

func TestRun_ConfigFile(t *testing.T) {
	files := map[string]string{
		"warn.yml":   warnPipeline,
		".glsec.yml": "strict: true\n",
	}
	if code, _, stderr := runCLI(t, files, "warn.yml"); code != 1 {
		t.Fatalf("strict: true in .glsec.yml should fail on warnings, got %d; stderr:\n%s", code, stderr)
	}

	files[".glsec.yml"] = "strict: [not, a, bool\n"
	if code, _, _ := runCLI(t, files, "warn.yml"); code != 2 {
		t.Fatalf("an unreadable config should exit 2, got %d", code)
	}
}

func TestRun_Formats(t *testing.T) {
	files := map[string]string{"error.yml": errorPipeline}
	tests := []struct {
		format string
		check  func(t *testing.T, out string)
	}{
		{"text", func(t *testing.T, out string) {
			if !strings.Contains(out, "error[GL001]") {
				t.Errorf("text output lacks error[GL001]:\n%s", out)
			}
		}},
		{"table", func(t *testing.T, out string) {
			if !strings.Contains(out, "GL001") || !strings.Contains(out, "SEVERITY") {
				t.Errorf("table output lacks header or GL001:\n%s", out)
			}
		}},
		{"json", func(t *testing.T, out string) {
			var v struct {
				Findings []struct {
					Rule string `json:"rule"`
				} `json:"findings"`
			}
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("json output does not parse: %v\n%s", err, out)
			}
			if len(v.Findings) == 0 {
				t.Errorf("json output has no findings:\n%s", out)
			}
		}},
		{"sarif", func(t *testing.T, out string) {
			var v struct {
				Version string `json:"version"`
				Runs    []struct {
					Results []json.RawMessage `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("sarif output does not parse: %v", err)
			}
			if v.Version != "2.1.0" || len(v.Runs) != 1 || len(v.Runs[0].Results) == 0 {
				t.Errorf("unexpected sarif structure: version %q, %d runs", v.Version, len(v.Runs))
			}
		}},
		{"codeclimate", func(t *testing.T, out string) {
			var v []map[string]any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("codeclimate output does not parse: %v", err)
			}
			if len(v) == 0 {
				t.Error("codeclimate output is empty")
			}
		}},
		{"junit", func(t *testing.T, out string) {
			var v struct {
				XMLName xml.Name
			}
			if err := xml.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("junit output does not parse: %v", err)
			}
			if !strings.Contains(out, "GL001") {
				t.Error("junit output lacks GL001")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, files, "--format", tt.format, "error.yml")
			if code != 1 {
				t.Fatalf("exit %d, want 1; stderr:\n%s", code, stderr)
			}
			tt.check(t, stdout)
		})
	}
}

func TestRun_OnlyAndSkip(t *testing.T) {
	files := map[string]string{"error.yml": errorPipeline}

	_, stdout, _ := runCLI(t, files, "--format", "json", "--only", "GL053", "error.yml")
	if strings.Contains(stdout, "GL001") || !strings.Contains(stdout, "GL053") {
		t.Errorf("--only GL053 should report GL053 and nothing else:\n%s", stdout)
	}

	code, stdout, _ := runCLI(t, files, "--format", "json", "--skip", "gl001", "error.yml")
	if code != 0 || strings.Contains(stdout, "GL001") {
		t.Errorf("--skip gl001 should drop GL001 (case-insensitive) and exit 0, got %d:\n%s", code, stdout)
	}

	_, _, stderr := runCLI(t, files, "--only", "GL01,GL001", "error.yml")
	if !strings.Contains(stderr, `unknown rule ID "GL01"`) {
		t.Errorf("a typo in --only should warn, stderr:\n%s", stderr)
	}
}

func TestRun_RequireIgnoreReason(t *testing.T) {
	noReason := strings.Replace(errorPipeline, "node:latest", "node:latest # glsec:ignore GL001", 1)
	withReason := strings.Replace(errorPipeline, "node:latest", "node:latest # glsec:ignore GL001 -- pinned by renovate", 1)

	if code, _, _ := runCLI(t, map[string]string{"p.yml": noReason}, "p.yml"); code != 0 {
		t.Errorf("a suppressed error should exit 0 without the policy, got %d", code)
	}
	code, _, stderr := runCLI(t, map[string]string{"p.yml": noReason}, "--require-ignore-reason", "p.yml")
	if code != 2 || !strings.Contains(stderr, "without a reason") {
		t.Errorf("a suppression without reason should exit 2 under --require-ignore-reason, got %d; stderr:\n%s", code, stderr)
	}
	if code, _, _ := runCLI(t, map[string]string{"p.yml": withReason}, "--require-ignore-reason", "p.yml"); code != 0 {
		t.Errorf("a suppression with a reason should pass the policy, got %d", code)
	}
}

func TestRun_GenerateIgnoreThenClean(t *testing.T) {
	dirFiles := map[string]string{"error.yml": errorPipeline}
	code, _, stderr := runCLI(t, dirFiles, "--generate-ignore", "error.yml")
	if code != 0 || !strings.Contains(stderr, "suppression(s) to .glsec-ignore") {
		t.Fatalf("--generate-ignore should exit 0 and report, got %d; stderr:\n%s", code, stderr)
	}
	data, err := os.ReadFile(".glsec-ignore")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "error.yml:2 GL001") {
		t.Fatalf(".glsec-ignore lacks the GL001 entry:\n%s", data)
	}

	// Same directory: the baseline now suppresses every finding.
	var out, errOut bytes.Buffer
	if code := run([]string{"error.yml"}, &out, &errOut); code != 0 {
		t.Fatalf("after --generate-ignore the scan should exit 0, got %d; stderr:\n%s", code, errOut.String())
	}
	if code := run([]string{"--no-ignores", "error.yml"}, &out, &errOut); code != 1 {
		t.Fatalf("--no-ignores should bypass the baseline and exit 1, got %d", code)
	}
}

func TestRun_NewOnlyWithMissingBaseline(t *testing.T) {
	code, _, stderr := runCLI(t, map[string]string{"error.yml": errorPipeline}, "--baseline", "nope.json", "error.yml")
	if code != 2 || !strings.Contains(stderr, "--baseline") {
		t.Fatalf("an unreadable --baseline should exit 2, got %d; stderr:\n%s", code, stderr)
	}
}

func TestRun_VersionAndClearCache(t *testing.T) {
	code, stdout, _ := runCLI(t, nil, "--version")
	if code != 0 || !strings.HasPrefix(stdout, "glsec ") {
		t.Errorf("--version: exit %d, output %q", code, stdout)
	}
	code, _, stderr := runCLI(t, nil, "--clear-cache")
	if code != 0 || !strings.Contains(stderr, "cache cleared") {
		t.Errorf("--clear-cache: exit %d, stderr %q", code, stderr)
	}
}

func TestRun_List(t *testing.T) {
	code, stdout, _ := runCLI(t, nil, "list")
	if code != 0 || !strings.Contains(stdout, "rules total") || !strings.Contains(stdout, "GL001") {
		t.Fatalf("list: exit %d\n%s", code, stdout)
	}

	code, stdout, _ = runCLI(t, nil, "list", "--format", "json")
	var infos []ruleInfo
	if code != 0 || json.Unmarshal([]byte(stdout), &infos) != nil {
		t.Fatalf("list --format json: exit %d, output does not parse", code)
	}
	if len(infos) != len(rules.All()) {
		t.Errorf("list --format json has %d rules, want %d", len(infos), len(rules.All()))
	}
	for _, info := range infos {
		if info.Description == "" || info.Severity == "" {
			t.Errorf("%s lacks a description or severity from its docs file", info.ID)
		}
	}

	_, stdout, _ = runCLI(t, nil, "list", "--format", "json", "--owasp", "cicd-sec-4")
	infos = nil
	if err := json.Unmarshal([]byte(stdout), &infos); err != nil || len(infos) == 0 {
		t.Fatalf("list --owasp cicd-sec-4 returned nothing (err %v)", err)
	}
	for _, info := range infos {
		if !containsFold(info.OWASP, "CICD-SEC-4") {
			t.Errorf("%s does not map to CICD-SEC-4 but was listed", info.ID)
		}
	}

	if code, _, _ := runCLI(t, nil, "list", "--format", "xml"); code != 2 {
		t.Errorf("list --format xml should exit 2, got %d", code)
	}
	if code, _, _ := runCLI(t, nil, "list", "--bogus"); code != 2 {
		t.Errorf("list --bogus should exit 2, got %d", code)
	}
}

func TestRun_Explain(t *testing.T) {
	code, stdout, _ := runCLI(t, nil, "explain", "gl001", "--no-color")
	if code != 0 {
		t.Fatalf("explain gl001: exit %d", code)
	}
	for _, want := range []string{"GL001 — ", "Severity:", "Risk:", "Docs: "} {
		if !strings.Contains(stdout, want) {
			t.Errorf("explain output lacks %q:\n%s", want, stdout)
		}
	}

	tests := [][]string{
		{"explain"},
		{"explain", "--no-color"},
		{"explain", "GL999"},
	}
	for _, args := range tests {
		if code, _, _ := runCLI(t, nil, args...); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
	}
}

func TestRun_ExplainEveryRule(t *testing.T) {
	for _, r := range rules.All() {
		code, stdout, stderr := runCLI(t, nil, "explain", r.ID())
		if code != 0 || !strings.HasPrefix(stdout, r.ID()+" — ") {
			t.Errorf("explain %s: exit %d, stderr %q", r.ID(), code, stderr)
		}
	}
}

func TestWrapWords(t *testing.T) {
	got := wrapWords("one two three four five", 9)
	want := []string{"one two", "three", "four five"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("wrapWords = %q, want %q", got, want)
	}
	if got := wrapWords("   ", 10); len(got) != 0 {
		t.Errorf("wrapWords on blanks = %q, want none", got)
	}
}
