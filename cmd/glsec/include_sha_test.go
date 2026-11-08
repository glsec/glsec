// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestRun_RequireIncludeSHA(t *testing.T) {
	const pipeline = "include:\n  - project: acme/e\n    ref: v1.2.3\n    file: /e.yml\n  - component: gitlab.example.invalid/acme/g@1.2.3\njob:\n  script: [make]\n"
	for _, tc := range []struct {
		name, config   string
		args           []string
		code, findings int
	}{
		{"default", "", nil, 0, 0},
		{"disabled", "require_include_sha: false\n", nil, 0, 0},
		{"enabled", "require_include_sha: true\n", nil, 0, 2},
		{"strict", "require_include_sha: true\n", []string{"--strict"}, 1, 2},
		{"untrusted repo config", "require_include_sha: true\n", []string{"--no-repo-config"}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{".gitlab-ci.yml": pipeline}
			if tc.config != "" {
				files[".glsec.yml"] = tc.config
			}
			args := append([]string{"--no-cache", "--only", "GL003,GL041", "--format", "json"}, tc.args...)
			code, out, stderr := runCLI(t, files, args...)
			got := strings.Count(out, `"rule": "GL003"`) + strings.Count(out, `"rule": "GL041"`)
			if code != tc.code || got != tc.findings {
				t.Fatalf("exit %d, output %s, stderr %s; want exit %d and %d findings", code, out, stderr, tc.code, tc.findings)
			}
			// A subsequent scan with default config must reset the singletons.
			code, out, stderr = runCLI(t, map[string]string{".gitlab-ci.yml": pipeline}, "--no-cache", "--only", "GL003,GL041", "--format", "json")
			if code != 0 || strings.Contains(out, `"rule": "GL0`) {
				t.Fatalf("policy leaked into default scan: exit %d, %s, %s", code, out, stderr)
			}
		})
	}
}
