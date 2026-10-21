// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func TestLoad_SymlinkedEntryIsAMiss(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	planted := filepath.Join(t.TempDir(), "planted.json")
	if err := os.WriteFile(planted, []byte(`{"findings":[],"job_count":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(planted, filepath.Join(Dir(), "k.json")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	if _, ok := Load("k"); ok {
		t.Error("a symbolic link in place of an entry must be a miss")
	}
}

func TestStore_ReplacesSymlinkInsteadOfWritingThrough(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	target := filepath.Join(t.TempDir(), "precious")
	if err := os.WriteFile(target, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(Dir(), "k.json")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	Store("k", &Entry{Findings: []finding.Finding{{RuleID: "GL001"}}})
	if data, _ := os.ReadFile(target); string(data) != "precious\n" { //nolint:gosec // G304: the test's own temp file
		t.Errorf("Store wrote through the symbolic link: %q", data)
	}
	if got, ok := Load("k"); !ok || len(got.Findings) != 1 {
		t.Error("the entry was not stored in place of the link")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(Dir(), "*.tmp")); len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}
}

func TestLoadAndStore_WritableByOthersIsIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits don't express sharing on Windows")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	Store("k", &Entry{Findings: []finding.Finding{{RuleID: "GL001"}}})
	if err := os.Chmod(Dir(), 0o777); err != nil { //nolint:gosec // G302: the point of the test
		t.Fatal(err)
	}
	if _, ok := Load("k"); ok {
		t.Error("an entry in a directory others can write to must be a miss")
	}
	Store("k2", &Entry{})
	if _, err := os.Stat(filepath.Join(Dir(), "k2.json")); err == nil {
		t.Error("Store wrote into a directory others can write to")
	}
}
