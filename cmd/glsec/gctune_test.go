// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestGCHeldBeforeRegexpsCompile pins the package order gctune relies on: Go
// initialises packages by import path, so renaming it could move it behind the
// packages whose start it is there to speed up (#1236).
func TestGCHeldBeforeRegexpsCompile(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // G204: re-runs this test binary
	cmd.Env = append(os.Environ(), "GODEBUG=inittrace=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	trace := string(out)
	gc := strings.Index(trace, "init github.com/glsec/glsec/internal/gctune ")
	if gc < 0 {
		t.Fatalf("no gctune in the init trace: %s", trace)
	}
	for _, pkg := range []string{"internal/redact", "rules"} {
		at := strings.Index(trace, "init github.com/glsec/glsec/"+pkg+" ")
		if at < 0 {
			t.Fatalf("no %s in the init trace: %s", pkg, trace)
		}
		if at < gc {
			t.Errorf("%s initialises before gctune", pkg)
		}
	}
}
