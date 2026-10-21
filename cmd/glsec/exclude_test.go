// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestMatchesExclude(t *testing.T) {
	tests := []struct {
		file    string
		pattern string
		want    bool
	}{
		{"vendor/a.yml", "vendor/", true},
		{"vendor", "vendor/", true},
		{"vendor/deep/a.yml", "vendor/", true},
		{"vendorx/a.yml", "vendor/", false}, // same prefix, different directory
		{"infra/old/x/y.yml", "infra/old/**", true},
		{"infra/older/y.yml", "infra/old/**", false},
		{"legacy/.gitlab-ci.yml", "legacy/.gitlab-ci.yml", true},
		{"./legacy/.gitlab-ci.yml", "legacy/.gitlab-ci.yml", true},
		{"legacy/.gitlab-ci.yml", "./legacy/.gitlab-ci.yml", true},
		{"./vendor/a.yml", "./vendor/", true},
		{"sub/../vendor/a.yml", "vendor/", true},
		{"a.yml", "*.yml", true},
		{"sub/a.yml", "*.yml", false}, // * does not cross /
		{"sub/a.yml", "sub/*.yml", true},
		{"other/.gitlab-ci.yml", "legacy/.gitlab-ci.yml", false},
		{"a.yml", "[bad", false}, // malformed glob never matches
	}
	for _, tt := range tests {
		if got := matchesExclude(tt.file, []string{tt.pattern}); got != tt.want {
			t.Errorf("matchesExclude(%q, %q) = %v, want %v", tt.file, tt.pattern, got, tt.want)
		}
	}

	if matchesExclude("a.yml", nil) {
		t.Error("no patterns should exclude nothing")
	}
	if !matchesExclude("b.yml", []string{"a.yml", "b.yml"}) {
		t.Error("any matching pattern should exclude")
	}
}

func TestMatchesExclude_WindowsPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("backslash is a path separator only on Windows")
	}
	file := filepath.Join("legacy", ".gitlab-ci.yml")
	for _, pat := range []string{`legacy\.gitlab-ci.yml`, "legacy/.gitlab-ci.yml", `legacy\`} {
		if !matchesExclude(file, []string{pat}) {
			t.Errorf("matchesExclude(%q, %q) = false, want true", file, pat)
		}
	}
}
