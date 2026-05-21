package shellcheck

import (
	"testing"

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
