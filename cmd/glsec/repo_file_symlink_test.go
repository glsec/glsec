// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runWithLink runs glsec in a repository whose file name is a symbolic link to
// target, a path relative to the directory that holds the repository.
func runWithLink(t *testing.T, name, target string, args ...string) (code int, stderr string, dir string) {
	t.Helper()
	dir = t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o750); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(repo, ".gitlab-ci.yml"): "job:\n  script: [echo]\n",
		filepath.Join(repo, "inside.txt"):     "",
		filepath.Join(dir, "outside.txt"):     "precious\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, target), filepath.Join(repo, name)); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	t.Chdir(repo)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	var out, errOut bytes.Buffer
	code = run(append([]string{"--no-cache"}, args...), &out, &errOut)
	return code, errOut.String(), dir
}

func TestRepoFileSymlinks(t *testing.T) {
	outside := "outside.txt"
	inside := filepath.Join("repo", "inside.txt")
	tests := []struct {
		name, file, target string
		args               []string
		refuse             bool
	}{
		{"config out of the repository", ".glsec.yml", outside, nil, true},
		{"config inside the repository", ".glsec.yml", inside, nil, false},
		{"config out, but --no-repo-config", ".glsec.yml", outside, []string{"--no-repo-config"}, false},
		{"config out, but explicit --config", ".glsec.yml", outside, []string{"--config", "inside.txt"}, false},
		{"ignore file out of the repository", ".glsec-ignore", outside, nil, true},
		{"ignore file out, but --no-ignores", ".glsec-ignore", outside, []string{"--no-ignores"}, false},
		{"ignore file out, --generate-ignore", ".glsec-ignore", outside, []string{"--generate-ignore"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stderr, dir := runWithLink(t, tt.file, tt.target, tt.args...)
			refused := strings.Contains(stderr, "symbolic link to a file outside the working directory")
			if refused != tt.refuse || (code == 2) != tt.refuse {
				t.Errorf("exit code %d, refused %v, want refused %v; stderr:\n%s", code, refused, tt.refuse, stderr)
			}
			if data, _ := os.ReadFile(filepath.Join(dir, "outside.txt")); string(data) != "precious\n" { //nolint:gosec // G304: the test's own temp dir
				t.Errorf("the file outside the repository was overwritten: %q", data)
			}
		})
	}
}
