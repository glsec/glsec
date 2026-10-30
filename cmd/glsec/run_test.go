// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/shellcheck"
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
	setupCLI(t, files)
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// setupCLI writes files into a temporary directory and changes into it, with
// the environment runCLI runs glsec in.
func setupCLI(t *testing.T, files map[string]string) {
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

}

// A typo in --only drops a rule the user asked for, so it stops the scan; a
// typo in --skip leaves the rule running and only warns (#900).
func TestRun_UnknownRuleIDs(t *testing.T) {
	files := map[string]string{"error.yml": errorPipeline}
	for _, tc := range []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"typo alone in --only", []string{"--only", "GL0O1"}, 2, `error: --only: unknown rule ID "GL0O1"`},
		{"typo next to a valid ID", []string{"--only", "GL01,GL001"}, 2, `error: --only: unknown rule ID "GL01"`},
		{"two typos, both named", []string{"--only", "GLX,GL01"}, 2, `unknown rule ID "GL01", "GLX"`},
		{"--only and --skip cancel out", []string{"--skip", "GL001", "--only", "GL001"}, 2, "leave no rule to run"},
		{"typo in --skip only warns", []string{"--skip", "GL01"}, 1, `warning: --skip: unknown rule ID "GL01"`},
		{"ShellCheck code is accepted", []string{"--only", "GL001,SC2086"}, 1, ""},
		{"--skip narrows --only", []string{"--only", "GL001,GL053", "--skip", "GL053"}, 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, files, append(tc.args, "error.yml")...)
			if code != tc.wantCode {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, tc.wantCode, stderr)
			}
			if tc.wantErr != "" && !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr lacks %q:\n%s", tc.wantErr, stderr)
			}
			if tc.wantErr == "" && strings.Contains(stderr, "unknown rule ID") {
				t.Errorf("unexpected unknown-ID message:\n%s", stderr)
			}
		})
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
	for _, want := range []string{"GL001 — ", "Severity:", "Risk:", "Docs: https://glsec.github.io/rules/GL001/\n"} {
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

func TestParseExplainDoc_CRLF(t *testing.T) {
	raw, err := os.ReadFile("../../docs/rules/GL001.md")
	if err != nil {
		t.Fatal(err)
	}
	lf := parseExplainDoc(raw)
	crlf := parseExplainDoc([]byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")))
	if crlf != lf {
		t.Errorf("CRLF docs parse differently:\nLF:   %+v\nCRLF: %+v", lf, crlf)
	}
	if lf.risk == "" || lf.title == "" {
		t.Errorf("GL001 docs parsed without title or risk: %+v", lf)
	}
}

// Every flag glsec accepts is documented in the README (#696).
func TestReadmeDocumentsEveryFlag(t *testing.T) {
	var stderr bytes.Buffer
	run([]string{"-h"}, io.Discard, &stderr)
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	flags := regexp.MustCompile(`(?m)^\s+-([a-z][a-z-]*)`).FindAllStringSubmatch(stderr.String(), -1)
	if len(flags) < 10 {
		t.Fatalf("found only %d flags in the usage text:\n%s", len(flags), stderr.String())
	}
	for _, m := range flags {
		if !regexp.MustCompile(`--` + m[1] + `(?:[^a-z-]|$)`).Match(readme) {
			t.Errorf("--%s is not mentioned in README.md", m[1])
		}
	}
}

// TestReadmeGoInstallPath checks that every go install command in the README
// names this package (#716).
func TestReadmeGoInstallPath(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	paths := regexp.MustCompile(`go install (github\.com/glsec/glsec\S*)@`).FindAllSubmatch(readme, -1)
	if len(paths) == 0 {
		t.Fatal("README.md has no go install command")
	}
	for _, m := range paths {
		if got := string(m[1]); got != "github.com/glsec/glsec/cmd/glsec" {
			t.Errorf("README.md installs %s, but the main package is github.com/glsec/glsec/cmd/glsec", got)
		}
	}
}

// TestEveryRuleHasAPage checks that every rule's SARIF helpUri is its page on
// the website, which is built from docs/rules/<ID>.md (#718).
func TestEveryRuleHasAPage(t *testing.T) {
	for _, r := range rules.All() {
		id := r.ID()
		if got, want := output.RuleURL(id), "https://glsec.github.io/rules/"+id+"/"; got != want {
			t.Errorf("RuleURL(%s) = %q, want %q", id, got, want)
		}
		if _, err := os.Stat(filepath.Join("..", "..", "docs", "rules", id+".md")); err != nil {
			t.Errorf("%s has no docs/rules/%s.md to build its page from", id, id)
		}
	}
}

// The gitlab-sast report takes rule titles, CWE and OWASP IDs from the rule
// metadata (#846).
func TestRun_FormatGitLabSAST(t *testing.T) {
	code, stdout, stderr := runCLI(t, map[string]string{".gitlab-ci.yml": errorPipeline}, "--format", "gitlab-sast", ".gitlab-ci.yml")
	if code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, stderr)
	}
	var r struct {
		Version         string `json:"version"`
		Vulnerabilities []struct {
			Name        string `json:"name"`
			Severity    string `json:"severity"`
			Identifiers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifiers"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if r.Version != output.GitLabSASTSchemaVersion {
		t.Errorf("version = %q", r.Version)
	}
	var gl001 bool
	for _, v := range r.Vulnerabilities {
		if !strings.HasPrefix(v.Name, "GL001: ") || v.Severity != "High" {
			continue
		}
		gl001 = true
		types := map[string]string{}
		for _, id := range v.Identifiers {
			types[id.Type] = id.Value
		}
		if types["glsec_rule"] != "GL001" || types["cwe"] != "1104" || types["owasp_cicd"] == "" {
			t.Errorf("GL001 identifiers = %+v", v.Identifiers)
		}
	}
	if !gl001 {
		t.Errorf("no titled High GL001 vulnerability in %s", stdout)
	}
}

// The example of #908: GitLab runs job2 and never sees job.
func TestRun_SpecHeaderScansLastDocument(t *testing.T) {
	src := "spec:\n  inputs: {}\n---\njob:\n  image: node:latest\n  script: [a]\n---\njob2:\n  image: ruby:latest\n  script: [b]\n"
	_, stdout, stderr := runCLI(t, map[string]string{".gitlab-ci.yml": src},
		"--no-cache", "--no-repo-config", "--only", "GL001", "--format", "json", ".gitlab-ci.yml")
	var out struct {
		Findings []struct {
			Job string `json:"job"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("parse JSON output: %v\n%s", err, stdout)
	}
	if len(out.Findings) != 1 || out.Findings[0].Job != "job2" {
		t.Errorf("GL001 findings = %+v, want one for job2", out.Findings)
	}
	if !strings.Contains(stderr, ".gitlab-ci.yml:4: document ignored") {
		t.Errorf("stderr does not warn about the ignored document:\n%s", stderr)
	}
}

// The example of #937: GitLab runs workflow: and default: as jobs here.
func TestRun_KeywordJobsAreScanned(t *testing.T) {
	src := "workflow:\n  image: node:latest\n  script: [./build.sh]\ndefault:\n  image: ruby:latest\n  script: [./deploy.sh]\nreal:\n  script: [x]\n"
	_, stdout, stderr := runCLI(t, map[string]string{".gitlab-ci.yml": src},
		"--no-cache", "--no-repo-config", "--only", "GL001", "--format", "json", ".gitlab-ci.yml")
	var out struct {
		Findings []struct {
			Job string `json:"job"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("parse JSON output: %v\n%s", err, stdout)
	}
	jobs := map[string]bool{}
	for _, f := range out.Findings {
		jobs[f.Job] = true
	}
	if !jobs["workflow"] || !jobs["default"] || jobs["real"] || len(jobs) != 2 {
		t.Errorf("GL001 findings for jobs %v, want workflow and default only (real must not inherit ruby:latest)", jobs)
	}
	if !strings.Contains(stderr, `GitLab runs it as a job named "workflow"`) {
		t.Errorf("stderr does not warn about the keyword job:\n%s", stderr)
	}
}

// #831: no format prints a detected secret, and positions stay the same.
// Values are built at run time, so the file holds no real-looking token.
func TestRun_SecretsAreMaskedInEveryFormat(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("aB3", 12)
	pw := "hunter2" + "pass99"
	src := "variables:\n  GH: \"" + ghp + "\"\njob:\n  script:\n    - curl -fsSL https://user:" + pw + "@example.com/install.sh | bash\n    - curl -u admin:" + pw + " https://api.example.com\n    - 'curl -H \"Authorization: Bearer $API_TOKEN\" https://api.example.com'\n"
	files := map[string]string{".gitlab-ci.yml": src}
	for _, format := range []string{"text", "table", "json", "sarif", "codeclimate", "junit", "gitlab-sast"} {
		_, stdout, _ := runCLI(t, files, "--no-cache", "--no-repo-config", "--format", format, ".gitlab-ci.yml")
		if strings.Contains(stdout, ghp) || strings.Contains(stdout, pw) {
			t.Errorf("%s output shows a secret:\n%s", format, stdout)
		}
		if !strings.Contains(stdout, "GL006") {
			t.Errorf("%s output has no GL006 finding:\n%s", format, stdout)
		}
	}

	_, text, _ := runCLI(t, files, "--no-cache", "--no-repo-config", ".gitlab-ci.yml")
	if !strings.Contains(text, `GH: "ghp_`+strings.Repeat("*", 36)+`"`) {
		t.Errorf("text output should mask the token and keep its prefix:\n%s", text)
	}
	if !strings.Contains(text, ".gitlab-ci.yml:2:7") {
		t.Errorf("the GL006 position moved:\n%s", text)
	}

	_, raw, _ := runCLI(t, files, "--no-cache", "--no-repo-config", "--no-redact", ".gitlab-ci.yml")
	if !strings.Contains(raw, ghp) {
		t.Errorf("--no-redact should show the value:\n%s", raw)
	}
}

// #907: with ShellCheck turned on, a ShellCheck that crashes or hangs fails
// the scan with exit 2 and says why; a missing binary still only warns.
func TestRun_FailingShellcheckFailsTheScan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stand-ins are shell scripts")
	}
	old := shellcheck.Timeout
	shellcheck.Timeout = 300 * time.Millisecond
	t.Cleanup(func() { shellcheck.Timeout = old })
	files := map[string]string{
		".glsec.yml": "shellcheck:\n  enabled: true\n",
		"ci.yml":     "j1:\n  script: [echo $X]\nj2:\n  script: [echo $Y]\n",
		"sc-crash":   "#!/bin/sh\necho boom >&2; exit 3\n",
		// Without exec: sleep is a child of the killed shell and keeps the
		// output pipe open.
		"sc-hang": "#!/bin/sh\nsleep 30\n",
	}
	for _, tc := range []struct {
		bin, want string
		code      int
	}{
		{"./sc-crash", `error: ci.yml: shellcheck: job "j1": exit status 3: boom`, 2},
		{"./sc-hang", `error: ci.yml: shellcheck: job "j1": did not finish within 300ms`, 2},
		{"./no-such-shellcheck", "", 0}, // warns on stderr and goes on
	} {
		t.Run(tc.bin, func(t *testing.T) {
			setupCLI(t, files)
			for _, f := range []string{"sc-crash", "sc-hang"} {
				if err := os.Chmod(f, 0o700); err != nil { //nolint:gosec // G302: a test stand-in must be executable
					t.Fatal(err)
				}
			}
			start := time.Now()
			var out, errOut bytes.Buffer
			code := run([]string{"--no-cache", "--shellcheck-path", tc.bin, "ci.yml"}, &out, &errOut)
			if code != tc.code || !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("exit %d, stderr:\n%s\nwant exit %d and %q", code, errOut.String(), tc.code, tc.want)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("the scan took %s", d)
			}
		})
	}
}

// A file glsec can't scan must not make the report look clean: the reports
// carry the error next to the findings of the files that were scanned (#809).
func TestRun_ScanErrorInReport(t *testing.T) {
	files := map[string]string{"error.yml": errorPipeline, "broken.yml": brokenPipeline}
	for format, want := range map[string]string{
		"json":        `"errors": [`,
		"codeclimate": `"check_name": "glsec-error"`,
		"sarif":       `"executionSuccessful": false`,
		"junit":       `<error message="parse broken.yml`,
		"gitlab-sast": `"status": "failure"`,
	} {
		t.Run(format, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, files, "--format", format, "error.yml", "broken.yml")
			if code != 2 {
				t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
			}
			if !strings.Contains(stdout, want) || !strings.Contains(stdout, "broken.yml") {
				t.Errorf("report lacks the scan error (%s):\n%s", want, stdout)
			}
			if !strings.Contains(stdout, "GL001") {
				t.Errorf("report lacks the findings of the file that was scanned:\n%s", stdout)
			}
			if !strings.Contains(stderr, "error: parse broken.yml") {
				t.Errorf("stderr lacks the error:\n%s", stderr)
			}
		})
	}

	t.Run("strict with every file excluded", func(t *testing.T) {
		code, stdout, _ := runCLI(t, files, "--strict", "--exclude", "*.yml", "--format", "json", "error.yml")
		if code != 2 || !strings.Contains(stdout, "nothing was scanned") {
			t.Errorf("exit %d, report:\n%s", code, stdout)
		}
	})
	t.Run("clean report unchanged", func(t *testing.T) {
		_, stdout, _ := runCLI(t, files, "--format", "json", "error.yml")
		if strings.Contains(stdout, `"errors"`) {
			t.Errorf("report of a successful scan has errors:\n%s", stdout)
		}
	})
}

func TestWriteOutput_MasksSecretsInScanErrors(t *testing.T) {
	token := "ghp_" + strings.Repeat("aB3", 12)
	errs := []output.ScanError{{File: "ci.yml", Message: "ci.yml: bad value " + token}}
	for _, mask := range []bool{true, false} {
		var buf bytes.Buffer
		if err := writeOutput(&buf, output.FormatJSON, nil, nil, errs, 0, false, false, mask); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(buf.String(), token); got == mask {
			t.Errorf("mask=%v: token in report = %v:\n%s", mask, got, buf.String())
		}
	}
}
