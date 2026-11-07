// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestGenerateIgnoreDoesNotWriteAfterScanErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		args  []string
	}{
		{"malformed root", map[string]string{".gitlab-ci.yml": brokenPipeline}, nil},
		{"mixed files", map[string]string{"good.yml": errorPipeline, "bad.yml": brokenPipeline}, []string{"good.yml", "bad.yml"}},
		{"required include", map[string]string{".gitlab-ci.yml": "include: missing.yml\n" + errorPipeline}, []string{"--strict"}},
		{"all excluded", map[string]string{".gitlab-ci.yml": errorPipeline}, []string{"--strict", "--exclude", ".gitlab-ci.yml"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, existing := range []bool{false, true} {
				name := "without baseline"
				if existing {
					name = "with baseline"
				}
				t.Run(name, func(t *testing.T) {
					files := make(map[string]string, len(tc.files)+1)
					for name, src := range tc.files {
						files[name] = src
					}
					const original = "# reviewed baseline\n.gitlab-ci.yml:2 GL001 exp:2999-01-01\ngood.yml:2 GL001\n"
					if existing {
						files[".glsec-ignore"] = original
					}
					args := append([]string{"--no-cache", "--generate-ignore", "--only", "GL001"}, tc.args...)
					code, out, stderr := runCLI(t, files, args...)
					if code != 2 || !strings.Contains(stderr, "error:") || strings.Contains(stderr, "wrote ") || out != "" {
						t.Fatalf("exit %d, stdout %s, stderr %s; want failed scan without baseline output", code, out, stderr)
					}
					data, err := os.ReadFile(".glsec-ignore")
					if existing {
						if err != nil || string(data) != original {
							t.Fatalf("baseline changed: %q, err=%v", data, err)
						}
					} else if !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("baseline created: %q, err=%v", data, err)
					}
				})
			}
		})
	}
}
