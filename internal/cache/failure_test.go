package cache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// noHome makes os.UserHomeDir fail on every OS and leaves XDG_CACHE_HOME
// unset, so Dir has nowhere to put the cache.
func noHome(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("home", "") // plan9
}

func TestDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", base)
	if got, want := Dir(), filepath.Join(base, "glsec"); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}

	home := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if got, want := Dir(), filepath.Join(home, ".cache", "glsec"); got != want {
		t.Errorf("Dir() without XDG_CACHE_HOME = %q, want %q", got, want)
	}

	noHome(t)
	if got := Dir(); got != "" {
		t.Errorf("Dir() without any home = %q, want empty", got)
	}
}

func TestNoCacheDirIsANoOp(t *testing.T) {
	noHome(t)
	Store("k", &Entry{JobCount: 1})
	if _, ok := Load("k"); ok {
		t.Error("Load without a cache dir must miss")
	}
	if err := Clear(); err != nil {
		t.Errorf("Clear without a cache dir: %v", err)
	}
}

func TestLoad_CorruptEntryIsAMiss(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(), "bad.json"), []byte(`{"findings": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := Load("bad"); ok {
		t.Error("a truncated cache entry must be a miss, not empty findings")
	}
}

func TestLoad_UnreadableEntryIsAMiss(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	// A directory where the entry should be can't be read on any OS.
	if err := os.MkdirAll(filepath.Join(Dir(), "dir.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok := Load("dir"); ok {
		t.Error("an unreadable cache entry must be a miss")
	}
}

func TestStore_UnwritableDirDoesNotFail(t *testing.T) {
	// XDG_CACHE_HOME is a regular file, so the cache dir can't be created.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", blocker)

	Store("k", &Entry{Findings: []finding.Finding{{RuleID: "GL001"}}})
	if _, ok := Load("k"); ok {
		t.Error("nothing could be stored, so Load must miss")
	}
}

func TestClear_KeepsOtherFiles(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	Store("k", &Entry{})
	other := filepath.Join(Dir(), "notes.txt")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if _, ok := Load("k"); ok {
		t.Error("Clear left a cache entry behind")
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("Clear removed a file that isn't a cache entry: %v", err)
	}
}

func TestKey_MissingAndUnreadableFiles(t *testing.T) {
	dir := t.TempDir()
	ci := filepath.Join(dir, "ci.yml")
	key := func(t *testing.T) (string, error) {
		t.Helper()
		return Key("v", "2026-10-15", "", []string{ci}, filepath.Join(dir, ".glsec.yml"), filepath.Join(dir, ".glsec-ignore"), nil, nil, nil)
	}

	missing, err := key(t)
	if err != nil {
		t.Fatalf("a missing pipeline or config file must not fail the key: %v", err)
	}
	if err := os.WriteFile(ci, []byte("job: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	present, err := key(t)
	if err != nil {
		t.Fatal(err)
	}
	if missing == present {
		t.Error("a file appearing must change the key")
	}

	// A config path that exists but can't be read as a file must not produce a
	// key, so the caller scans instead of trusting a cache entry.
	if err := os.Mkdir(filepath.Join(dir, ".glsec.yml"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := key(t); err == nil {
		t.Error("an unreadable config file must make Key fail")
	}
}

func TestKey_DiffersOnConfigAndExcludes(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".glsec.yml")
	base := func(excl []string) string {
		t.Helper()
		k, err := Key("v", "d", "", nil, cfg, "", excl, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	noCfg := base(nil)
	if err := os.WriteFile(cfg, []byte("strict: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withCfg := base(nil)
	if noCfg == withCfg {
		t.Error("adding .glsec.yml must change the key")
	}
	if base([]string{"a/", "b/"}) != base([]string{"b/", "a/"}) {
		t.Error("exclude order must not change the key")
	}
	if base([]string{"a/"}) == withCfg {
		t.Error("an exclude pattern must change the key")
	}
}
