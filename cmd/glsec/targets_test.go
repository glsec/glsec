package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
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

	got, err := resolveTargets([]string{a, b}, false, nil)
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

	got, err := resolveTargets([]string{filepath.Join(dir, "*.yml")}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 glob matches, got %v", got)
	}
}

func TestResolveTargets_NoMatchErrors(t *testing.T) {
	if _, err := resolveTargets([]string{"/no/such/path-xyz.yml"}, false, nil); err == nil {
		t.Error("expected error for non-existent file with no glob match")
	}
}

func TestResolveTargets_Recursive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitlab-ci.yml"))
	writeFile(t, filepath.Join(dir, "nested", "deep", ".gitlab-ci.yml"))
	writeFile(t, filepath.Join(dir, "nested", "other.yml"))    // not named .gitlab-ci.yml
	writeFile(t, filepath.Join(dir, ".git", ".gitlab-ci.yml")) // inside .git — skipped

	got, err := resolveTargets([]string{dir}, true, nil)
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
	if _, err := resolveTargets([]string{dir}, true, nil); err == nil {
		t.Error("expected error when no .gitlab-ci.yml files are found recursively")
	}
}

func TestResolveTargets_RecursiveBasenamePattern(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitlab-ci.yml"))
	writeFile(t, filepath.Join(dir, "svc", "build.gitlab-ci.yml"))
	writeFile(t, filepath.Join(dir, "svc", "other.yml"))

	got, err := resolveTargets([]string{dir}, true, []string{"*.gitlab-ci.yml"})
	if err != nil {
		t.Fatal(err)
	}
	// .gitlab-ci.yml (default) + build.gitlab-ci.yml (pattern); other.yml excluded.
	if len(got) != 2 {
		t.Fatalf("expected 2 matches, got %v", got)
	}
}

func TestResolveTargets_RecursiveRelativePathPattern(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "repo", "ci", "pipeline.yml"))
	writeFile(t, filepath.Join(dir, "repo", "ci", "other.yml"))

	got, err := resolveTargets([]string{dir}, true, []string{"repo/ci/pipeline.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 path-pattern match, got %v", got)
	}
}

func TestResolveTargets_RecursiveNoDoubleCount(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitlab-ci.yml"))

	// .gitlab-ci.yml matches the default and the pattern — must appear once.
	got, err := resolveTargets([]string{dir}, true, []string{"*.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped match, got %v", got)
	}
}

func TestResolveTargets_RecursiveBadPattern(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitlab-ci.yml"))
	if _, err := resolveTargets([]string{dir}, true, []string{"["}); err == nil {
		t.Error("expected error for malformed glob pattern")
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
