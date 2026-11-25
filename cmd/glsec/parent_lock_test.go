// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// gl019Files runs a JSON scan of the root file and returns, sorted, the files
// that have a GL019 finding.
func gl019Files(t *testing.T, files map[string]string, args ...string) []string {
	t.Helper()
	_, stdout, stderr := runCLI(t, files, append([]string{"--format", "json", "--only", "GL019"}, args...)...)
	var out struct {
		Findings []jsonFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("json: %v\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	var got []string
	for _, f := range out.Findings {
		got = append(got, filepath.ToSlash(f.File))
	}
	sort.Strings(got)
	return got
}

const deployJob = `apply:
  script: [./apply.sh]
  environment: production
`

// lockedTrigger starts path as a child pipeline under the resource_group
// prod; strategy is the trigger:strategy line, empty for none.
func lockedTrigger(name, path, strategy string) string {
	s := name + ":\n  resource_group: prod\n  trigger:\n    include: " + path + "\n"
	if strategy != "" {
		s += "    strategy: " + strategy + "\n"
	}
	return s
}

func TestGL019_ParentLock(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			name: "resource_group and strategy depend lock the child",
			files: map[string]string{
				".gitlab-ci.yml": lockedTrigger("prod", "child.yml", "depend"),
				"child.yml":      deployJob,
			},
		},
		{
			name: "strategy mirror locks the child too",
			files: map[string]string{
				".gitlab-ci.yml": lockedTrigger("prod", "child.yml", "mirror"),
				"child.yml":      deployJob,
			},
		},
		{
			name: "without strategy the lock is released when the child starts",
			files: map[string]string{
				".gitlab-ci.yml": lockedTrigger("prod", "child.yml", ""),
				"child.yml":      deployJob,
			},
			want: []string{"child.yml"},
		},
		{
			name: "strategy without resource_group holds no lock",
			files: map[string]string{
				".gitlab-ci.yml": "prod:\n  trigger:\n    include: child.yml\n    strategy: depend\n",
				"child.yml":      deployJob,
			},
			want: []string{"child.yml"},
		},
		{
			name: "one unlocked trigger leaves the child unlocked",
			files: map[string]string{
				".gitlab-ci.yml": lockedTrigger("prod", "child.yml", "depend") +
					"adhoc:\n  trigger:\n    include: child.yml\n",
				"child.yml": deployJob,
			},
			want: []string{"child.yml"},
		},
		{
			name: "a grandchild the locked child waits on is locked",
			files: map[string]string{
				".gitlab-ci.yml": lockedTrigger("prod", "child.yml", "depend"),
				"child.yml":      "next:\n  trigger:\n    include: grand.yml\n    strategy: depend\n",
				"grand.yml":      deployJob,
			},
		},
		{
			name: "a grandchild the locked child does not wait on is not",
			files: map[string]string{
				".gitlab-ci.yml": lockedTrigger("prod", "child.yml", "depend"),
				"child.yml":      "next:\n  trigger:\n    include: grand.yml\n",
				"grand.yml":      deployJob,
			},
			want: []string{"grand.yml"},
		},
		{
			name: "a file the locked child includes runs under the lock",
			files: map[string]string{
				".gitlab-ci.yml": lockedTrigger("prod", "child.yml", "depend"),
				"child.yml":      "include:\n  - local: deploy.yml\n",
				"deploy.yml":     deployJob,
			},
		},
		{
			name: "the parent's own deploy job is still checked",
			files: map[string]string{
				".gitlab-ci.yml": lockedTrigger("prod", "child.yml", "depend") + deployJob,
				"child.yml":      deployJob,
			},
			want: []string{".gitlab-ci.yml"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gl019Files(t, tc.files)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("GL019 in %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGL019_ChildScannedAloneStillReported(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": lockedTrigger("prod", "child.yml", "depend"),
		"child.yml":      deployJob,
	}
	got := gl019Files(t, files, "child.yml")
	if strings.Join(got, ",") != "child.yml" {
		t.Errorf("GL019 in %v, want [child.yml]", got)
	}
}
