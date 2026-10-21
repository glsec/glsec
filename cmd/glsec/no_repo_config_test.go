// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestNoRepoConfig(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "job:\n  image: node:latest\n  script: [echo]\n",
		".glsec.yml":     "rules:\n  GL001: off\nexclude_paths: [\".gitlab-ci.yml\"]\n",
		"mine.yml":       "rules:\n  GL001: off\n",
	}
	tests := []struct {
		name     string
		args     []string
		want     []string
		wantNote bool
	}{
		{"repo config applies by default", nil, nil, false},
		{"--no-repo-config ignores it", []string{"--no-repo-config"}, []string{".gitlab-ci.yml"}, true},
		{"an explicit --config still applies", []string{"--no-repo-config", "--config", "mine.yml"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, stderr := gl001Files(t, files, append(tt.args, ".gitlab-ci.yml")...)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("GL001 in %v, want %v; stderr:\n%s", got, tt.want, stderr)
			}
			if hasNote := strings.Contains(stderr, ".glsec.yml is ignored (--no-repo-config)"); hasNote != tt.wantNote {
				t.Errorf("note on stderr = %v, want %v:\n%s", hasNote, tt.wantNote, stderr)
			}
		})
	}
}
