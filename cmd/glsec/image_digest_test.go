// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/cache"
)

// The cache key covers the config: a warm entry must not outlive a policy
// change. The test runs under CI=true with --cache, the mode a project that
// keeps the cache in CI uses, so it means the same locally and in CI.
func TestRun_RequireImageDigestCache(t *testing.T) {
	setupCLI(t, map[string]string{
		".glsec.yml":     "require_image_digest: true\n",
		".gitlab-ci.yml": "job:\n  image: node:22.1.0\n  script: [make]\n",
	})
	t.Setenv("CI", "true")
	scan := func() (int, string, string) {
		var out, stderr bytes.Buffer
		code := run([]string{"--cache", "--only", "GL001", "--format", "json"}, &out, &stderr)
		return code, out.String(), stderr.String()
	}

	if code, out, stderr := scan(); code != 0 || !strings.Contains(out, "GL001") {
		t.Fatalf("initial scan: exit %d, %s, %s", code, out, stderr)
	}
	repo, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if withinRoot(repo, cache.Dir()) {
		t.Fatalf("cache %s is inside the scanned repository %s", cache.Dir(), repo)
	}
	entries, err := filepath.Glob(filepath.Join(cache.Dir(), "*.json"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("%d cache entries, want 1 (%v)", len(entries), err)
	}

	// Only a scan that reads the entry can report this message.
	const marker = "message from the cache entry"
	key := strings.TrimSuffix(filepath.Base(entries[0]), ".json")
	entry, ok := cache.Load(key)
	if !ok || len(entry.Findings) != 1 {
		t.Fatalf("stored entry: %+v, loaded %v", entry, ok)
	}
	entry.Findings[0].Message = marker
	cache.Store(key, entry)
	if code, out, stderr := scan(); code != 0 || !strings.Contains(out, marker) {
		t.Fatalf("unchanged input missed the cache: exit %d, %s, %s", code, out, stderr)
	}

	if err := os.WriteFile(".glsec.yml", []byte("require_image_digest: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := scan(); code != 0 || strings.Contains(out, "GL001") || strings.Contains(out, marker) {
		t.Fatalf("stale policy finding after config change: exit %d, %s, %s", code, out, stderr)
	}
}

func TestRun_RequireImageDigest(t *testing.T) {
	const pipeline = "job:\n  image: node:22.1.0\n  services: [redis:7.2.4]\n  script: [make]\n"
	for _, tc := range []struct {
		name, config   string
		args           []string
		code, findings int
	}{
		{"default", "", nil, 0, 0},
		{"disabled", "require_image_digest: false\n", nil, 0, 0},
		{"enabled", "require_image_digest: true\n", nil, 0, 2},
		{"strict", "require_image_digest: true\n", []string{"--strict"}, 1, 2},
		{"rule disabled", "require_image_digest: true\nrules: {GL001: off}\n", nil, 0, 0},
		{"severity override", "require_image_digest: true\nrules: {GL001: error}\n", nil, 1, 2},
		{"untrusted repo config", "require_image_digest: true\n", []string{"--no-repo-config"}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{".gitlab-ci.yml": pipeline}
			if tc.config != "" {
				files[".glsec.yml"] = tc.config
			}
			args := append([]string{"--no-cache", "--only", "GL001", "--format", "json"}, tc.args...)
			code, out, stderr := runCLI(t, files, args...)
			if code != tc.code || strings.Count(out, `"rule": "GL001"`) != tc.findings {
				t.Fatalf("exit %d, output %s, stderr %s; want exit %d and %d findings", code, out, stderr, tc.code, tc.findings)
			}
			// A subsequent scan with default config must reset the singleton.
			code, out, stderr = runCLI(t, map[string]string{".gitlab-ci.yml": pipeline}, "--no-cache", "--only", "GL001", "--format", "json")
			if code != 0 || strings.Contains(out, "GL001") {
				t.Fatalf("policy leaked into default scan: exit %d, %s, %s", code, out, stderr)
			}
		})
	}
}
