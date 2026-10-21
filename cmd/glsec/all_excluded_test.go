// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestAllFilesExcluded(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "job:\n  image: node:latest\n  script: [echo]\n",
		".glsec.yml":     "exclude_paths: [\".gitlab-ci.yml\"]\n",
	}
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantMsg  string
	}{
		{"warns by default", nil, 0, "warning: every file to scan matches exclude_paths"},
		{"fails with --strict", []string{"--strict"}, 2, "error: every file to scan matches exclude_paths"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, files, append(tt.args, ".gitlab-ci.yml")...)
			if code != tt.wantCode {
				t.Errorf("exit code %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stderr, tt.wantMsg) {
				t.Errorf("stderr lacks %q:\n%s", tt.wantMsg, stderr)
			}
		})
	}
}

func TestSomeFilesExcludedNoWarning(t *testing.T) {
	files := map[string]string{
		"a/.gitlab-ci.yml": "job:\n  script: [echo]\n",
		"b/.gitlab-ci.yml": "job:\n  script: [echo]\n",
	}
	_, _, stderr := runCLI(t, files, "--exclude", "a/", "a/.gitlab-ci.yml", "b/.gitlab-ci.yml")
	if strings.Contains(stderr, "nothing was scanned") {
		t.Errorf("warned although b/.gitlab-ci.yml was scanned:\n%s", stderr)
	}
}
