// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheInsideScannedRepositoryIsNotUsed(t *testing.T) {
	for _, tt := range []struct {
		name    string
		inside  bool
		entries int
	}{
		{"cache inside the repository", true, 0},
		{"cache elsewhere", false, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			if err := os.WriteFile(filepath.Join(repo, ".gitlab-ci.yml"), []byte("job:\n  script: [echo]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cacheHome := t.TempDir()
			if tt.inside {
				cacheHome = filepath.Join(repo, ".cache")
			}
			t.Chdir(repo)
			t.Setenv("XDG_CACHE_HOME", cacheHome)
			t.Setenv("CI", "") // CI turns the cache off (#898)
			var out, errOut bytes.Buffer
			run([]string{".gitlab-ci.yml"}, &out, &errOut)
			entries, _ := filepath.Glob(filepath.Join(cacheHome, "glsec", "*.json"))
			if len(entries) != tt.entries {
				t.Errorf("%d cache entries, want %d", len(entries), tt.entries)
			}
		})
	}
}

// In CI the cache is off unless --cache asks for it, and --no-cache wins (#898).
func TestCacheInCI(t *testing.T) {
	for _, tt := range []struct {
		name    string
		ci      string
		args    []string
		entries int
	}{
		{"local", "", nil, 1},
		{"CI", "true", nil, 0},
		{"CI with --cache", "true", []string{"--cache"}, 1},
		{"CI with --cache --no-cache", "true", []string{"--cache", "--no-cache"}, 0},
		{"CI=false", "false", nil, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo, cacheHome := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(repo, ".gitlab-ci.yml"), []byte("job:\n  script: [echo]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(repo)
			t.Setenv("XDG_CACHE_HOME", cacheHome)
			t.Setenv("CI", tt.ci)
			var out, errOut bytes.Buffer
			if code := run(append(tt.args, ".gitlab-ci.yml"), &out, &errOut); code == 2 {
				t.Fatalf("exit 2: %s", errOut.String())
			}
			entries, _ := filepath.Glob(filepath.Join(cacheHome, "glsec", "*.json"))
			if len(entries) != tt.entries {
				t.Errorf("%d cache entries, want %d", len(entries), tt.entries)
			}
		})
	}
}
