// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package shellcheck

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

func parseSeq(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// root → DocumentNode → SequenceNode
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		return root.Content[0]
	}
	return &root
}

func TestExtractLines_SimpleScalars(t *testing.T) {
	seq := parseSeq(t, "- echo hello\n- echo world\n")
	lines := extractLines(seq)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	if lines[0].content != "echo hello" {
		t.Errorf("unexpected content: %q", lines[0].content)
	}
	if lines[1].content != "echo world" {
		t.Errorf("unexpected content: %q", lines[1].content)
	}
}

func TestExtractLines_YAMLLineNumbers(t *testing.T) {
	src := "- echo first\n- echo second\n- echo third\n"
	seq := parseSeq(t, src)
	lines := extractLines(seq)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for i, l := range lines {
		expected := i + 1
		if l.yamlLine != expected {
			t.Errorf("line %d: expected yamlLine=%d, got %d", i, expected, l.yamlLine)
		}
	}
}

func TestExtractLines_BlockScalar(t *testing.T) {
	src := "- |\n  set -e\n  apt-get install -y curl\n"
	seq := parseSeq(t, src)
	lines := extractLines(seq)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines from block scalar, got %d", len(lines))
	}
	if lines[0].content != "set -e" {
		t.Errorf("unexpected content[0]: %q", lines[0].content)
	}
	if lines[1].content != "apt-get install -y curl" {
		t.Errorf("unexpected content[1]: %q", lines[1].content)
	}
	// block scalar: | is on line 1, content starts on line 2
	if lines[0].yamlLine != 2 {
		t.Errorf("expected yamlLine=2 for first block line, got %d", lines[0].yamlLine)
	}
	if lines[1].yamlLine != 3 {
		t.Errorf("expected yamlLine=3 for second block line, got %d", lines[1].yamlLine)
	}
}

func TestExtractLines_Empty(t *testing.T) {
	lines := extractLines(nil)
	if len(lines) != 0 {
		t.Errorf("expected nil input to return empty slice")
	}
}

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		level string
		want  string
	}{
		{"error", "error"},
		{"warning", "warn"},
		{"info", "info"},
		{"style", "info"},
	}
	for _, tc := range cases {
		got := string(mapSeverity(tc.level))
		if got != tc.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestExtractLines_UnresolvedReference(t *testing.T) {
	ref := parseSeq(t, "!reference [.from_include, script]\n")
	if ref.Tag != "!reference" {
		t.Fatalf("test input is not a !reference: %q", ref.Tag)
	}
	if lines := extractLines(ref); lines != nil {
		t.Errorf("an unresolved !reference holds a path, not commands, got %v", lines)
	}
}

// fakeShellCheck writes an executable that appends each script it is given to
// a log, separated by "--", and reports one SC2086 warning at column 6 of line
// $FAKE_SC_LINE, or of the first line when that is unset.
func fakeShellCheck(t *testing.T) (bin, log string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake ShellCheck is a shell script")
	}
	dir := t.TempDir()
	log = filepath.Join(dir, "log")
	bin = filepath.Join(dir, "sc")
	script := "#!/bin/sh\n" +
		"for f; do :; done\n" + // the script path is the last argument
		"cat \"$f\" >> '" + log + "'\necho -- >> '" + log + "'\n" +
		`echo "{\"comments\":[{\"line\":${FAKE_SC_LINE:-1},\"column\":6,\"level\":\"warning\",\"code\":2086,\"message\":\"Double quote to prevent globbing.\"}]}"` + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test helper must be executable
		t.Fatal(err)
	}
	return bin, log
}

// invocations returns the scripts the fake ShellCheck was run on.
func invocations(t *testing.T, log string) []string {
	t.Helper()
	data, err := os.ReadFile(log) //nolint:gosec // the test's own temp file
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(data), "--\n")
	return parts[:len(parts)-1]
}

func runOn(t *testing.T, bin, src string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Run(doc.Root, "test.yml", bin)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRun_JobHooks(t *testing.T) {
	bin, log := fakeShellCheck(t)
	f := runOn(t, bin, `build:
  hooks:
    pre_get_sources_script:
      - echo $GIT_STRATEGY
  script: []
`)
	if len(f) != 1 || f[0].RuleID != "SC2086" || f[0].Job != "build" || f[0].Line != 4 || f[0].Severity != finding.Warn {
		t.Fatalf("expected one SC2086 on the hook line of job build, got %+v", f)
	}
	if got := invocations(t, log); len(got) != 1 || got[0] != "echo $GIT_STRATEGY\n" {
		t.Errorf("expected ShellCheck to see only the hook, got %q", got)
	}
}

func TestRun_EmptySectionsAreNotChecked(t *testing.T) {
	bin, log := fakeShellCheck(t)
	f := runOn(t, bin, `before_script: []
default:
  after_script: []
  hooks:
    pre_get_sources_script: []
build:
  before_script: []
  script:
    - echo $X
  after_script: []
steps:
  run:
    - name: noop
      func: registry.example.com/fn:1
`)
	if got := invocations(t, log); len(got) != 1 || got[0] != "echo $X\n" {
		t.Errorf("expected exactly one ShellCheck run, on the one non-empty section, got %q", got)
	}
	if len(f) != 1 || f[0].Line != 9 {
		t.Errorf("expected one finding on line 9, got %+v", f)
	}
}

func TestExtractLines_NonStringItems(t *testing.T) {
	seq := parseSeq(t, "- echo a\n- key: value\n- [nested]\n- echo b\n")
	lines := extractLines(seq)
	if len(lines) != 2 || lines[0].content != "echo a" || lines[1].content != "echo b" || lines[1].yamlLine != 4 {
		t.Errorf("non-string items must be skipped, got %+v", lines)
	}
}

func TestExtractLines_MultiLinePlainScalar(t *testing.T) {
	// A plain scalar over several lines folds into one command.
	lines := extractLines(parseSeq(t, "- echo a\n  echo b\n"))
	if len(lines) != 1 || lines[0].content != "echo a echo b" || lines[0].yamlLine != 1 {
		t.Errorf("got %+v, want one folded command on line 1", lines)
	}
	// With a blank line it keeps a line break. Unlike | and >, the content
	// starts on the item's own line, so the first line must not shift by one.
	// The folded second line can't be traced back to line 3, so it's reported
	// where the scalar starts and marked approximate (#753).
	lines = extractLines(parseSeq(t, "- echo c\n\n  echo d\n"))
	if len(lines) != 2 || lines[0].content != "echo c" || lines[0].yamlLine != 1 || lines[0].approximate {
		t.Errorf("got %+v, want the first command exactly on line 1", lines)
	}
	if lines[1].content != "echo d" || lines[1].yamlLine != 1 || !lines[1].approximate {
		t.Errorf("got %+v, want the second command at the scalar's start, approximate", lines[1])
	}
}

func TestRun_ApproximateLineHasNoColumn(t *testing.T) {
	bin, _ := fakeShellCheck(t)
	t.Setenv("FAKE_SC_LINE", "2") // the script's second line
	for _, tc := range []struct {
		name, src string
		line, col int
	}{
		{"literal block keeps line and column", "build:\n  script:\n    - |\n      echo ok\n      echo $X\n", 5, 6},
		{"folded plain line traced to its source", "build:\n  script:\n    - echo ok\n\n      echo $X\n", 5, 6},
		{"untraceable quoted line has no column", "build:\n  script:\n    - \"echo \\\"ok\\\"\n\n      echo $X\"\n", 3, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := runOn(t, bin, tc.src)
			if len(f) != 1 || f[0].Line != tc.line || f[0].Col != tc.col {
				t.Errorf("got %+v, want line %d column %d", f, tc.line, tc.col)
			}
		})
	}
}
