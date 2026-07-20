package suppress

import (
	"os"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// testNow is a fixed reference date; entries without an expiry are
// unaffected by it, so these tests stay deterministic.
var testNow = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

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
			if !m.IsSuppressed(line, "GL001", testNow) {
				t.Errorf("GL001 should be suppressed on line %d", line)
			}
			if m.IsSuppressed(line, "GL002", testNow) {
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
	if m.IsSuppressed(1, "GL001", testNow) {
		t.Error("nothing should be suppressed in a document without ignore comments")
	}
}

func TestFromComment_SCCode(t *testing.T) {
	sups := fromComment("# glsec:ignore SC2086", 7)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].RuleID != "SC2086" {
		t.Errorf("expected SC2086, got %q", sups[0].RuleID)
	}
}

func TestFromComment_SCCodeWithReason(t *testing.T) {
	sups := fromComment("# glsec:ignore SC2086 -- CI variable always set by platform", 3)
	if len(sups) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(sups))
	}
	if sups[0].RuleID != "SC2086" {
		t.Errorf("expected SC2086, got %q", sups[0].RuleID)
	}
	if sups[0].Reason != "CI variable always set by platform" {
		t.Errorf("unexpected reason: %q", sups[0].Reason)
	}
}

func TestIsSuppressed_MissingLine(t *testing.T) {
	m := Map{}
	if m.IsSuppressed(99, "GL001", testNow) {
		t.Error("should not be suppressed on a line not in the map")
	}
}

func TestMerge(t *testing.T) {
	a := Map{1: {"GL001": Entry{Reason: "reason a"}}}
	b := Map{1: {"GL002": Entry{}}, 2: {"GL003": Entry{}}}
	a.Merge(b)
	if !a.IsSuppressed(1, "GL001", testNow) {
		t.Error("GL001 on line 1 should still be suppressed after merge")
	}
	if !a.IsSuppressed(1, "GL002", testNow) {
		t.Error("GL002 on line 1 should be suppressed after merge")
	}
	if !a.IsSuppressed(2, "GL003", testNow) {
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
	if !m.IsSuppressed(7, "GL001", testNow) {
		t.Error("GL001 on line 7 should be suppressed")
	}
	if !m.IsSuppressed(14, "GL002", testNow) {
		t.Error("GL002 on line 14 should be suppressed")
	}
	// Entry for other.yml should not appear for .gitlab-ci.yml
	if m.IsSuppressed(3, "GL001", testNow) {
		t.Error("GL001 on line 3 from other.yml should not be suppressed for .gitlab-ci.yml")
	}
}

func TestLoadIgnoreFile_Missing(t *testing.T) {
	m := LoadIgnoreFile("/nonexistent/.glsec-ignore", ".gitlab-ci.yml")
	if len(m) != 0 {
		t.Error("expected empty map for missing ignore file")
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse("2006-01-02", s)
	if err != nil {
		t.Fatalf("bad test date %q: %v", s, err)
	}
	return ts
}

func TestExpiry_InlineParsing(t *testing.T) {
	got := fromComment("# glsec:ignore GL001 exp:2026-12-01 -- accepted until the migration lands", 7)
	if len(got) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(got))
	}
	if got[0].RuleID != "GL001" || got[0].Expiry != "2026-12-01" {
		t.Errorf("rule/expiry = %q/%q", got[0].RuleID, got[0].Expiry)
	}
	if got[0].Reason != "accepted until the migration lands" {
		t.Errorf("reason = %q", got[0].Reason)
	}
}

func TestExpiry_Applies(t *testing.T) {
	now := mustTime(t, "2026-06-15")
	for _, tc := range []struct {
		name       string
		expiry     string
		suppressed bool
	}{
		{"no expiry never expires", "", true},
		{"future date still applies", "2026-12-01", true},
		{"expiry day itself still applies", "2026-06-15", true},
		{"past date no longer applies", "2026-06-14", false},
		{"malformed date fails closed", "2026-13-45", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Map{}
			m.set(4, "GL001", Entry{Expiry: tc.expiry})
			if got := m.IsSuppressed(4, "GL001", now); got != tc.suppressed {
				t.Errorf("IsSuppressed = %v, want %v", got, tc.suppressed)
			}
			// A suppression that no longer applies must be reported as expired,
			// so the caller can explain why the finding came back.
			if wantExpired := !tc.suppressed; m.ExpiredAt(4, "GL001", now) != wantExpired {
				t.Errorf("ExpiredAt = %v, want %v", !wantExpired, wantExpired)
			}
		})
	}
}

func TestExpiry_UnknownRuleIsNotExpired(t *testing.T) {
	now := mustTime(t, "2026-06-15")
	m := Map{}
	if m.IsSuppressed(1, "GL999", now) || m.ExpiredAt(1, "GL999", now) {
		t.Error("a rule with no suppression is neither suppressed nor expired")
	}
}

func TestLoadIgnoreFile_Expiry(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.glsec-ignore"
	content := "# generated\n" +
		".gitlab-ci.yml:4 GL001 exp:2026-12-01\n" +
		".gitlab-ci.yml:9 GL002\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	m := LoadIgnoreFile(path, ".gitlab-ci.yml")

	now := mustTime(t, "2026-06-15")
	if !m.IsSuppressed(4, "GL001", now) {
		t.Error("entry with a future expiry should still suppress")
	}
	if !m.IsSuppressed(9, "GL002", now) {
		t.Error("entry without an expiry should suppress, keeping older ignore files working")
	}
	after := mustTime(t, "2027-01-01")
	if m.IsSuppressed(4, "GL001", after) {
		t.Error("entry should stop suppressing once its expiry has passed")
	}
}
