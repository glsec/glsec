// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// fakeGlsec writes an executable that reports version and, when run with
// anything else, prints "ran <name>".
func fakeGlsec(t *testing.T, path, version, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { //nolint:gosec // G703: paths under the test's temp dir
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo \"glsec " + version + " (commit x, built y)\"; else echo \"ran " + name + "\"; fi\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // test helper must be executable
		t.Fatal(err)
	}
}

// TestWrapperBinaryLookup runs the Claude Code plugin wrapper (bin/glsec) with
// a prepared PATH and cache, so no download happens: whatever it does not take
// from PATH it takes from the cache.
func TestWrapperBinaryLookup(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the wrapper supports linux and darwin only")
	}
	wrapper, err := filepath.Abs(filepath.Join("..", "..", "bin", "glsec"))
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(wrapper) //nolint:gosec // G304: the wrapper in this repository
	if err != nil {
		t.Fatal(err)
	}
	version := regexp.MustCompile(`(?m)^VERSION="([0-9.]+)"`).FindSubmatch(src)[1]
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		t.Skip("unsupported architecture")
	}
	base := "/usr/bin:/bin"

	tests := []struct {
		name   string
		onPath string // version of the glsec in an absolute PATH entry, "" for none
		inCwd  bool   // a glsec in the working directory, reachable through an empty PATH entry
		want   string
	}{
		{"same version on PATH", string(version), false, "ran path"},
		{"newer version on PATH", "99.0.0", false, "ran path"},
		{"older version on PATH", "1.0.0", false, "ran cache"},
		{"unversioned build on PATH", "dev", false, "ran cache"},
		{"empty PATH entry", "", true, "ran cache"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cache := filepath.Join(dir, "cache")
			fakeGlsec(t, filepath.Join(cache, "glsec", "glsec-"+string(version)+"-"+runtime.GOOS+"-"+arch), string(version), "cache")
			path := base
			if tt.onPath != "" {
				fakeGlsec(t, filepath.Join(dir, "bin", "glsec"), tt.onPath, "path")
				path = filepath.Join(dir, "bin") + ":" + base
			}
			work := filepath.Join(dir, "work")
			if tt.inCwd {
				fakeGlsec(t, filepath.Join(work, "glsec"), string(version), "cwd")
				path = ":" + base
			} else if err := os.MkdirAll(work, 0o750); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/bin/sh", wrapper, ".gitlab-ci.yml") //nolint:gosec // G204: runs the wrapper in this repository
			cmd.Dir = work
			cmd.Env = []string{"PATH=" + path, "HOME=" + dir, "XDG_CACHE_HOME=" + cache}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("wrapper failed: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
