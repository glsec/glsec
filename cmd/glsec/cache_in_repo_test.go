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
			var out, errOut bytes.Buffer
			run([]string{".gitlab-ci.yml"}, &out, &errOut)
			entries, _ := filepath.Glob(filepath.Join(cacheHome, "glsec", "*.json"))
			if len(entries) != tt.entries {
				t.Errorf("%d cache entries, want %d", len(entries), tt.entries)
			}
		})
	}
}
