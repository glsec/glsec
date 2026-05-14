package suppress

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseNode(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return &root
}

func TestFromComment_Basic(t *testing.T) {
	sups := fromComment("# glsec:ignore GL001", 5)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].RuleID != "GL001" {
		t.Errorf("expected GL001, got %q", sups[0].RuleID)
	}
	if sups[0].Reason != "" {
		t.Errorf("expected no reason, got %q", sups[0].Reason)
	}
}

func TestFromComment_WithReason(t *testing.T) {
	sups := fromComment("# glsec:ignore GL002 -- approved by security team", 10)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].Reason != "approved by security team" {
		t.Errorf("unexpected reason: %q", sups[0].Reason)
	}
}

func TestFromComment_Empty(t *testing.T) {
	if sups := fromComment("", 1); len(sups) != 0 {
		t.Errorf("expected no suppressions from empty comment")
	}
}

func TestFromComment_NoMatch(t *testing.T) {
	if sups := fromComment("# just a regular comment", 1); len(sups) != 0 {
		t.Errorf("expected no suppressions")
	}
}

func TestBuild_IsSuppressed(t *testing.T) {
	src := `
build:
  image: node:latest  # glsec:ignore GL001 -- updated monthly via Renovate
  script:
    - npm ci
`
	root := parseNode(t, src)
	m := Build(root)

	// Find the line with the image node — it should have the suppression
	found := false
	for line, rules := range m {
		if _, ok := rules["GL001"]; ok {
			found = true
			if !m.IsSuppressed(line, "GL001") {
				t.Errorf("GL001 should be suppressed on line %d", line)
			}
			if m.IsSuppressed(line, "GL002") {
				t.Errorf("GL002 should NOT be suppressed on line %d", line)
			}
		}
	}
	if !found {
		t.Error("expected GL001 suppression to be found in document")
	}
}

func TestBuild_EmptyDocument(t *testing.T) {
	root := parseNode(t, "stages: [build]\n")
	m := Build(root)
	if m.IsSuppressed(1, "GL001") {
		t.Error("nothing should be suppressed in a document without ignore comments")
	}
}

func TestIsSuppressed_MissingLine(t *testing.T) {
	m := Map{}
	if m.IsSuppressed(99, "GL001") {
		t.Error("should not be suppressed on a line not in the map")
	}
}

func TestMerge(t *testing.T) {
	a := Map{1: {"GL001": "reason a"}}
	b := Map{1: {"GL002": ""}, 2: {"GL003": ""}}
	a.Merge(b)
	if !a.IsSuppressed(1, "GL001") {
		t.Error("GL001 on line 1 should still be suppressed after merge")
	}
	if !a.IsSuppressed(1, "GL002") {
		t.Error("GL002 on line 1 should be suppressed after merge")
	}
	if !a.IsSuppressed(2, "GL003") {
		t.Error("GL003 on line 2 should be suppressed after merge")
	}
}

func TestLoadIgnoreFile_Basic(t *testing.T) {
	content := "# comment\n.gitlab-ci.yml:7 GL001\n.gitlab-ci.yml:14 GL002\nother.yml:3 GL001\n"
	f, err := os.CreateTemp(t.TempDir(), "glsec-ignore-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	m := LoadIgnoreFile(f.Name(), ".gitlab-ci.yml")
	if !m.IsSuppressed(7, "GL001") {
		t.Error("GL001 on line 7 should be suppressed")
	}
	if !m.IsSuppressed(14, "GL002") {
		t.Error("GL002 on line 14 should be suppressed")
	}
	// Entry for other.yml should not appear for .gitlab-ci.yml
	if m.IsSuppressed(3, "GL001") {
		t.Error("GL001 on line 3 from other.yml should not be suppressed for .gitlab-ci.yml")
	}
}

func TestLoadIgnoreFile_Missing(t *testing.T) {
	m := LoadIgnoreFile("/nonexistent/.glsec-ignore", ".gitlab-ci.yml")
	if len(m) != 0 {
		t.Error("expected empty map for missing ignore file")
	}
}
