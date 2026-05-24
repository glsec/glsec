package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("build:\n  script: [echo hi]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveTargets_ExplicitFiles(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.yml")
	b := filepath.Join(dir, "b.yml")
	writeFile(t, a)
	writeFile(t, b)

	got, err := resolveTargets([]string{a, b}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %v", got)
	}
}

func TestResolveTargets_Glob(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "one.yml"))
	writeFile(t, filepath.Join(dir, "two.yml"))
	writeFile(t, filepath.Join(dir, "skip.txt"))

	got, err := resolveTargets([]string{filepath.Join(dir, "*.yml")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 glob matches, got %v", got)
	}
}

func TestResolveTargets_NoMatchErrors(t *testing.T) {
	if _, err := resolveTargets([]string{"/no/such/path-xyz.yml"}, false); err == nil {
		t.Error("expected error for non-existent file with no glob match")
	}
}

func TestResolveTargets_Recursive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitlab-ci.yml"))
	writeFile(t, filepath.Join(dir, "nested", "deep", ".gitlab-ci.yml"))
	writeFile(t, filepath.Join(dir, "nested", "other.yml"))    // not named .gitlab-ci.yml
	writeFile(t, filepath.Join(dir, ".git", ".gitlab-ci.yml")) // inside .git — skipped

	got, err := resolveTargets([]string{dir}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 .gitlab-ci.yml files (skipping .git and non-matching names), got %v", got)
	}
}

func TestResolveTargets_RecursiveNoneFound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pipeline.yml"))
	if _, err := resolveTargets([]string{dir}, true); err == nil {
		t.Error("expected error when no .gitlab-ci.yml files are found recursively")
	}
}

func TestDedupeStrings(t *testing.T) {
	got := dedupeStrings([]string{"a", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
