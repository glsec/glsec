// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const shellcheckPipeline = `job:
  script:
    - echo $X
`

// fakeShellCheck writes an executable that records that it ran and prints an
// empty ShellCheck result, and returns its path and the marker file's path.
func fakeShellCheck(t *testing.T) (bin, marker string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake ShellCheck is a shell script")
	}
	dir := t.TempDir()
	marker = filepath.Join(dir, "ran")
	bin = filepath.Join(dir, "sc")
	script := "#!/bin/sh\ntouch '" + marker + "'\necho '{\"comments\":[]}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test helper must be executable
		t.Fatal(err)
	}
	return bin, marker
}

func ran(marker string) bool {
	_, err := os.Stat(marker) //nolint:gosec // G703: marker is a path in the test's temp dir
	return err == nil
}

func TestShellCheckPath_IgnoredInDiscoveredConfig(t *testing.T) {
	bin, marker := fakeShellCheck(t)
	files := map[string]string{
		".gitlab-ci.yml": shellcheckPipeline,
		".glsec.yml":     "shellcheck:\n  enabled: true\n  path: " + bin + "\n",
	}
	_, _, stderr := runCLI(t, files, "--no-cache")
	if ran(marker) {
		t.Fatal("ran the binary named by shellcheck.path in a .glsec.yml found in the working directory")
	}
	if !strings.Contains(stderr, "shellcheck.path is ignored") {
		t.Errorf("expected a warning about the ignored path, got stderr:\n%s", stderr)
	}
}

func TestShellCheckPath_ExplicitConfig(t *testing.T) {
	bin, marker := fakeShellCheck(t)
	files := map[string]string{
		".gitlab-ci.yml": shellcheckPipeline,
		"trusted.yml":    "shellcheck:\n  enabled: true\n  path: " + bin + "\n",
	}
	_, _, stderr := runCLI(t, files, "--no-cache", "--config", "trusted.yml")
	if !ran(marker) {
		t.Fatalf("shellcheck.path from an explicit --config was not used; stderr:\n%s", stderr)
	}
	if strings.Contains(stderr, "shellcheck.path is ignored") {
		t.Errorf("no warning expected for an explicit --config, got:\n%s", stderr)
	}
}

func TestShellCheckPath_Flag(t *testing.T) {
	bin, marker := fakeShellCheck(t)
	other, otherMarker := fakeShellCheck(t)
	files := map[string]string{
		".gitlab-ci.yml": shellcheckPipeline,
		".glsec.yml":     "shellcheck:\n  enabled: true\n  path: " + other + "\n",
	}
	runCLI(t, files, "--no-cache", "--shellcheck-path", bin)
	if !ran(marker) {
		t.Fatal("--shellcheck-path was not used")
	}
	if ran(otherMarker) {
		t.Fatal("ran the path from .glsec.yml instead of --shellcheck-path")
	}
}
