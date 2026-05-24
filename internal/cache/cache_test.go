package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func TestStoreAndLoad(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	entry := &Entry{
		Findings: []finding.Finding{
			{RuleID: "GL001", Severity: finding.Error, File: "ci.yml", Line: 4, Message: "mutable tag"},
		},
		JobCount: 5,
	}

	Store("testkey", entry)

	got, ok := Load("testkey")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "GL001" {
		t.Errorf("unexpected findings: %+v", got.Findings)
	}
	if got.JobCount != 5 {
		t.Errorf("expected JobCount=5, got %d", got.JobCount)
	}
}

func TestLoad_Miss(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	_, ok := Load("doesnotexist")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestClear(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	Store("key1", &Entry{JobCount: 1})
	Store("key2", &Entry{JobCount: 2})

	if err := Clear(); err != nil {
		t.Fatal(err)
	}

	if _, ok := Load("key1"); ok {
		t.Error("expected key1 to be cleared")
	}
	if _, ok := Load("key2"); ok {
		t.Error("expected key2 to be cleared")
	}
}

func TestKey_Deterministic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ci.yml")
	if err := os.WriteFile(f, []byte("stages: [build]"), 0600); err != nil {
		t.Fatal(err)
	}

	k1, err := Key("v1.0.0", "16.0", []string{f}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Key("v1.0.0", "16.0", []string{f}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Errorf("key not deterministic: %q vs %q", k1, k2)
	}
}

func TestKey_DiffersOnContentChange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ci.yml")

	if err := os.WriteFile(f, []byte("stages: [build]"), 0600); err != nil {
		t.Fatal(err)
	}
	k1, err := Key("v1.0.0", "", []string{f}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(f, []byte("stages: [deploy]"), 0600); err != nil {
		t.Fatal(err)
	}
	k2, err := Key("v1.0.0", "", []string{f}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if k1 == k2 {
		t.Error("key should differ when file content changes")
	}
}

func TestKey_DiffersOnVersion(t *testing.T) {
	k1, _ := Key("v1.0.0", "", nil, "", "", nil, nil, nil)
	k2, _ := Key("v1.0.1", "", nil, "", "", nil, nil, nil)
	if k1 == k2 {
		t.Error("key should differ on version change")
	}
}

func TestKey_DiffersOnOnlySkip(t *testing.T) {
	base, _ := Key("v1.0.0", "", nil, "", "", nil, nil, nil)
	only, _ := Key("v1.0.0", "", nil, "", "", nil, []string{"GL001"}, nil)
	skip, _ := Key("v1.0.0", "", nil, "", "", nil, nil, []string{"GL001"})
	if base == only {
		t.Error("key should differ when --only is set")
	}
	if base == skip {
		t.Error("key should differ when --skip is set")
	}
	if only == skip {
		t.Error("--only and --skip with the same ID should produce different keys")
	}
}
