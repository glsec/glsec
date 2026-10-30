// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

const stdinPipeline = "build:\n  image: node:latest\n  script: [make]\n"

// runStdin runs glsec in a directory holding files, with input as stdin.
func runStdin(t *testing.T, files map[string]string, input string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	old := stdin
	stdin = strings.NewReader(input)
	t.Cleanup(func() { stdin = old })
	return runCLI(t, files, args...)
}

func TestRun_StdinSameAsFile(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": stdinPipeline}
	fileCode, fileOut, _ := runCLI(t, files, "--no-cache", "--format", "json", ".gitlab-ci.yml")
	code, out, stderr := runStdin(t, files, stdinPipeline, "--format", "json", "--stdin-filename", ".gitlab-ci.yml", "-")
	if code != fileCode || out != fileOut {
		t.Fatalf("stdin: exit %d, %s (stderr %s); file: exit %d, %s", code, out, stderr, fileCode, fileOut)
	}
	code, out, _ = runStdin(t, nil, stdinPipeline, "--format", "json", "-")
	if code != fileCode || out != strings.ReplaceAll(fileOut, `"file": ".gitlab-ci.yml"`, `"file": "\u003cstdin\u003e"`) {
		t.Fatalf("unnamed stdin: exit %d, %s", code, out)
	}
}

func TestRun_StdinFilenameInEveryFormat(t *testing.T) {
	for _, format := range []string{"text", "table", "json", "sarif", "codeclimate", "junit", "gitlab-sast"} {
		t.Run(format, func(t *testing.T) {
			_, out, stderr := runStdin(t, nil, stdinPipeline, "--format", format, "--stdin-filename", "ci/build.yml", "-")
			if !strings.Contains(out, "ci/build.yml") || strings.Contains(out, "<stdin>") {
				t.Fatalf("output doesn't name ci/build.yml: %s (stderr %s)", out, stderr)
			}
		})
	}
}

func TestRun_StdinSuppressions(t *testing.T) {
	inline := "build:\n  image: node:latest # glsec:ignore GL001 -- pinned by renovate\n  script: [make]\n"
	if code, out, stderr := runStdin(t, nil, inline, "--only", "GL001", "-"); code != 0 || strings.Contains(out, "GL001") {
		t.Fatalf("inline suppression ignored: exit %d, %s, %s", code, out, stderr)
	}
	files := map[string]string{".glsec-ignore": "ci.yml:2 GL001\n"}
	if code, out, stderr := runStdin(t, files, stdinPipeline, "--only", "GL001", "--stdin-filename", "ci.yml", "-"); code != 0 || strings.Contains(out, "GL001") {
		t.Fatalf(".glsec-ignore entry ignored: exit %d, %s, %s", code, out, stderr)
	}
	_, out, _ := runStdin(t, nil, stdinPipeline, "--only", "GL001", "--format", "json", "-")
	if !strings.Contains(out, `"line": 2`) {
		t.Fatalf("line number: %s", out)
	}
}

// GL078 and the text output's source lines use what was read from stdin, not
// the file --stdin-filename names, which holds something else (#833).
func TestRun_StdinNotReadAgainFromDisk(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": "build:\n  script: [make clean]\n"}
	staged := "build:\n  image: node:latest\n  script: [\"ma\u202eke\"]\n"
	_, out, stderr := runStdin(t, files, staged, "--no-color", "--stdin-filename", ".gitlab-ci.yml", "-")
	if !strings.Contains(out, "GL078") {
		t.Errorf("GL078 missed the bidi character on stdin: %s (stderr %s)", out, stderr)
	}
	if !strings.Contains(out, "image: node:latest") || strings.Contains(out, "make clean") {
		t.Errorf("source lines don't come from stdin: %s", out)
	}
}

func TestRun_StdinComponentTemplate(t *testing.T) {
	template := "spec:\n  inputs:\n    stage:\n      default: test\n---\nbuild:\n  stage: $[[ inputs.stage ]]\n  script: [make]\n"
	_, out, _ := runStdin(t, nil, template, "--only", "GL053", "--stdin-filename", "templates/x.yml", "-")
	if strings.Contains(out, "GL053") {
		t.Errorf("a component template got a whole-pipeline finding: %s", out)
	}
	_, out, _ = runStdin(t, nil, template, "--only", "GL053", "-")
	if !strings.Contains(out, "GL053") {
		t.Errorf("unnamed stdin is a root pipeline and should get GL053: %s", out)
	}
}

func TestRun_StdinLocalIncludes(t *testing.T) {
	files := map[string]string{"ci/jobs.yml": "lint:\n  image: alpine:latest\n  script: [make lint]\n"}
	root := "include:\n  - local: ci/jobs.yml\nbuild:\n  script: [make]\n"
	_, out, _ := runStdin(t, files, root, "--only", "GL001", "--format", "json", "--stdin-filename", ".gitlab-ci.yml", "-")
	if !strings.Contains(out, `"job": "lint"`) {
		t.Errorf("include not resolved with --stdin-filename: %s", out)
	}
	_, out, stderr := runStdin(t, files, root, "--only", "GL001", "--format", "json", "-")
	if strings.Contains(out, `"job": "lint"`) || !strings.Contains(stderr, "--stdin-filename") {
		t.Errorf("unnamed stdin: output %s, stderr %s; want the include skipped with a note", out, stderr)
	}
}

// The cache key hashes the files on disk, so stdin input must not use it.
func TestRun_StdinSkipsCache(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": stdinPipeline}
	setupCLI(t, files)
	for i, input := range []string{stdinPipeline, "build:\n  image: node:22.1.0\n  script: [make]\n"} {
		old := stdin
		stdin = strings.NewReader(input)
		var out, errOut bytes.Buffer
		code := run([]string{"--cache", "--only", "GL001", "--stdin-filename", ".gitlab-ci.yml", "-"}, &out, &errOut)
		stdin = old
		if want := 1 - i; code != want {
			t.Fatalf("run %d: exit %d, want %d: %s %s", i, code, want, &out, &errOut)
		}
	}
}

func TestRun_StdinErrors(t *testing.T) {
	old := parser.MaxFileSize
	parser.MaxFileSize = 64
	t.Cleanup(func() { parser.MaxFileSize = old })
	for _, tc := range []struct {
		name, input string
		args        []string
		stderr      string
	}{
		{"empty", "", []string{"-"}, "empty document"},
		{"invalid YAML", "build: [", []string{"-"}, "<stdin>"},
		{"too large", strings.Repeat("#", 65), []string{"-"}, "limit"},
		{"with a file", stdinPipeline, []string{"-", "other.yml"}, "can't be combined"},
		{"with --recursive", stdinPipeline, []string{"--recursive", "-"}, "can't be combined"},
		{"filename without -", stdinPipeline, []string{"--stdin-filename", "x.yml", "other.yml"}, "requires - as the file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runStdin(t, map[string]string{"other.yml": stdinPipeline}, tc.input, tc.args...)
			if code != 2 || !strings.Contains(stderr, tc.stderr) {
				t.Fatalf("exit %d, stderr %q; want exit 2 and %q", code, stderr, tc.stderr)
			}
		})
	}
}
