// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/parser"
)

// runCLIWithin is runCLI that fails instead of hanging. prepare runs in the
// test's working directory before glsec does, and may skip the test.
func runCLIWithin(t *testing.T, files map[string]string, prepare func(t *testing.T), args ...string) (int, string) {
	t.Helper()
	setupCLI(t, files)
	if prepare != nil {
		prepare(t)
	}
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		var out, errOut bytes.Buffer
		done <- result{run(args, &out, &errOut), errOut.String()}
	}()
	select {
	case r := <-done:
		return r.code, r.stderr
	case <-time.After(20 * time.Second):
		t.Fatal("glsec blocked")
		return 0, ""
	}
}

func mkfifoCLI(t *testing.T, name string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs on Windows")
	}
	if out, err := exec.Command("mkfifo", name).CombinedOutput(); err != nil { //nolint:gosec // G204: a test path in a temporary directory
		t.Skipf("mkfifo: %v %s", err, out)
	}
}

const childTrigger = "a:\n  trigger:\n    include: child.yml\nb:\n  image: alpine:3.20.3\n  script: [x]\n"

// #894: a FIFO, a directory or an oversized file fails cleanly, as the main
// file (exit 2) and as a child pipeline (skipped with a warning).
func TestRun_OnlyRegularFilesUpToTheLimit(t *testing.T) {
	old := parser.MaxFileSize
	parser.MaxFileSize = 1 << 20
	t.Cleanup(func() { parser.MaxFileSize = old })
	big := func(t *testing.T) {
		if err := os.WriteFile("big.yml", []byte("a:\n  script: [x]\n"+strings.Repeat("#\n", 1<<20)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name    string
		files   map[string]string
		prepare func(t *testing.T)
		arg     string
		code    int
		stderr  string
	}{
		{"main file is a FIFO", nil, func(t *testing.T) { mkfifoCLI(t, "ci.yml") }, "ci.yml", 2, "error: read ci.yml: not a regular file"},
		{"main file too large", nil, big, "big.yml", 2, "error: read big.yml: 2.0 MB, larger than the 1 MB limit"},
		{"child is a FIFO", map[string]string{".gitlab-ci.yml": childTrigger}, func(t *testing.T) { mkfifoCLI(t, "child.yml") }, ".gitlab-ci.yml", 0, "not a regular file"},
		{"child is a directory", map[string]string{".gitlab-ci.yml": childTrigger, "child.yml/keep": ""}, nil, ".gitlab-ci.yml", 0, "not a regular file"},
		{"child too large", map[string]string{".gitlab-ci.yml": childTrigger}, func(t *testing.T) {
			if err := os.WriteFile("child.yml", []byte(strings.Repeat("#\n", 1<<20)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, ".gitlab-ci.yml", 0, "larger than the 1 MB limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stderr := runCLIWithin(t, tc.files, tc.prepare, "--no-cache", "--no-repo-config", tc.arg)
			if code != tc.code || !strings.Contains(stderr, tc.stderr) {
				t.Errorf("exit %d, stderr:\n%s\nwant exit %d and %q", code, stderr, tc.code, tc.stderr)
			}
		})
	}
}
