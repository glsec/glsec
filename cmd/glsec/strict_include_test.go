// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const strictRootJob = "job:\n  script: [make]\n"

// A file of the pipeline that glsec could not read leaves part of it
// unchecked, so --strict fails the run (#1167).
func TestRun_StrictUnreadablePipelineFile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		file  string // the file that can't be read
	}{
		{"missing include", map[string]string{
			".gitlab-ci.yml": "include: missing.yml\n" + strictRootJob,
		}, "missing.yml"},
		{"missing include: local", map[string]string{
			".gitlab-ci.yml": "include:\n  - local: /ci/missing.yml\n" + strictRootJob,
		}, "ci/missing.yml"},
		{"unparsable include", map[string]string{
			".gitlab-ci.yml": "include: bad.yml\n" + strictRootJob,
			"bad.yml":        "job: [unclosed\n",
		}, "bad.yml"},
		{"include that is a list", map[string]string{
			".gitlab-ci.yml": "include: bad.yml\n" + strictRootJob,
			"bad.yml":        "- one\n- two\n",
		}, "bad.yml"},
		{"include that is a scalar", map[string]string{
			".gitlab-ci.yml": "include: bad.yml\n" + strictRootJob,
			"bad.yml":        "just text\n",
		}, "bad.yml"},
		{"child that is a list", map[string]string{
			".gitlab-ci.yml": "job:\n  trigger:\n    include: child.yml\n",
			"child.yml":      "- one\n",
		}, "child.yml"},
		{"missing child", map[string]string{
			".gitlab-ci.yml": "job:\n  trigger:\n    include: child.yml\n",
		}, "child.yml"},
		{"unparsable child", map[string]string{
			".gitlab-ci.yml": "job:\n  trigger:\n    include:\n      - local: child.yml\n",
			"child.yml":      "job: [unclosed\n",
		}, "child.yml"},
		{"nested", map[string]string{
			".gitlab-ci.yml": "include: a.yml\n" + strictRootJob,
			"a.yml":          "include: missing.yml\n",
		}, "missing.yml"},
		{"at the top of a Git repository", map[string]string{
			".gitlab-ci.yml": "include: missing.yml\n" + strictRootJob,
			".git/HEAD":      "ref: refs/heads/main\n",
		}, "missing.yml"},
		{"at the top of a worktree", map[string]string{
			".gitlab-ci.yml": "include: missing.yml\n" + strictRootJob,
			".git":           "gitdir: /elsewhere\n",
		}, "missing.yml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := runCLI(t, tc.files, "--strict", "--no-cache", "--format", "json", ".gitlab-ci.yml")
			if code != 2 || !strings.Contains(stderr, "error: ") {
				t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
			}
			var report struct {
				Errors []struct {
					File, Error string
				} `json:"errors"`
			}
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("%v in %s", err, out)
			}
			if len(report.Errors) != 1 || !strings.HasSuffix(filepath.ToSlash(report.Errors[0].File), tc.file) {
				t.Fatalf("want one error for %s, got %s", tc.file, out)
			}

			// Without --strict the same run only warns.
			code, _, stderr = runCLI(t, tc.files, "--no-cache", "--only", "GL001", ".gitlab-ci.yml")
			if code != 0 || !strings.Contains(stderr, "warning: ") {
				t.Fatalf("without --strict: exit %d, stderr:\n%s", code, stderr)
			}
		})
	}
}

func TestRun_StrictUnreadableFileInSARIF(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": "include: missing.yml\n" + strictRootJob}
	code, out, stderr := runCLI(t, files, "--strict", "--no-cache", "--format", "sarif", ".gitlab-ci.yml")
	if code != 2 || !strings.Contains(out, "missing.yml") || !strings.Contains(out, `"executionSuccessful": false`) {
		t.Fatalf("exit %d; stderr %s; report:\n%s", code, stderr, out)
	}
}

// The other files of the pipeline are still reported.
func TestRun_StrictUnreadableFileKeepsFindings(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "include:\n  - local: missing.yml\n  - local: ok.yml\njob:\n  image: node:latest\n  script: [make]\n",
		"ok.yml":         "other:\n  image: node:latest\n  script: [make]\n",
	}
	code, out, _ := runCLI(t, files, "--strict", "--no-cache", "--only", "GL001", "--format", "json", ".gitlab-ci.yml")
	if code != 2 || strings.Count(out, `"rule": "GL001"`) != 2 {
		t.Fatalf("exit %d, want 2 and two findings:\n%s", code, out)
	}
}

// Files GitLab doesn't need, or that glsec can't place, stay warnings.
func TestRun_StrictKeepsWarning(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		args  []string
		warn  string
	}{
		{"include with rules", map[string]string{
			"root.yml": "include:\n  - local: optional.yml\n    rules:\n      - exists: [optional.yml]\n" + strictRootJob,
		}, []string{"root.yml"}, "optional.yml"},
		{"nested in an include with rules", map[string]string{
			"root.yml": "include:\n  - local: a.yml\n    rules:\n      - exists: [a.yml]\n" + strictRootJob,
			"a.yml":    "include: missing.yml\n",
		}, []string{"root.yml"}, "missing.yml"},
		{"child path with a variable", map[string]string{
			"root.yml": "job:\n  trigger:\n    include: ci/$FLAVOUR.yml\n",
		}, []string{"root.yml"}, "$FLAVOUR"},
		{"scan below the repository root", map[string]string{
			".git/HEAD":     "ref: refs/heads/main\n",
			"ci/deploy.yml": "include: ci/common.yml\n" + strictRootJob,
			"ci/common.yml": strictRootJob,
		}, []string{"ci/deploy.yml"}, "ci/ci/common.yml"},
		{"outside the repository", map[string]string{
			"root.yml": "include: ../outside.yml\n" + strictRootJob,
		}, []string{"root.yml"}, "outside the repository"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--strict", "--no-cache", "--only", "GL001"}, tc.args...)
			code, _, stderr := runCLI(t, tc.files, args...)
			if code != 0 || !strings.Contains(stderr, "warning: ") || !strings.Contains(stderr, tc.warn) {
				t.Fatalf("exit %d, want 0 and a warning naming %q; stderr:\n%s", code, tc.warn, stderr)
			}
		})
	}
}

func TestRun_StrictIgnoresFilesItDoesNotRead(t *testing.T) {
	files := map[string]string{
		"root.yml": "include:\n  - local: excluded.yml\n  - local: $X/variable.yml\n  - remote: https://example.invalid/r.yml\n    integrity: sha256-L3/GAoKaw0Arw6hDCKeKQlV1QPEgHYxGBHsH4zG1IY8=\n" + strictRootJob,
	}
	code, _, stderr := runCLI(t, files, "--strict", "--no-cache", "--only", "GL001", "--exclude", "excluded.yml", "root.yml")
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestIsRepositoryRoot(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	sub := filepath.Join(repo, "ci")
	if err := os.MkdirAll(filepath.Join(sub, "deep"), 0o750); err != nil {
		t.Fatal(err)
	}
	if !isRepositoryRoot(sub) {
		t.Error("a directory in no repository counts as the root")
	}
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	if !isRepositoryRoot(repo) {
		t.Error("the directory holding .git is the root")
	}
	if isRepositoryRoot(sub) || isRepositoryRoot(filepath.Join(sub, "deep")) {
		t.Error("a directory below .git is not the root")
	}
}
