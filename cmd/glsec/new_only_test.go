// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func TestFilterNewOnly_JSONSnapshotBaseline(t *testing.T) {
	dir := t.TempDir()
	snap := dir + "/baseline.json"
	if err := os.WriteFile(snap, []byte(`{"findings":[{"rule":"GL001","file":"a.yml","line":2,"message":"old"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := []finding.Finding{
		{RuleID: "GL001", File: "a.yml", Line: 7, Message: "old"}, // drifted, in baseline
		{RuleID: "GL001", File: "a.yml", Line: 9, Message: "new"}, // not in baseline
	}
	got, err := filterNewOnly(io.Discard, findings, snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Message != "new" {
		t.Fatalf("expected only the new finding, got %+v", got)
	}
}

func TestFilterNewOnly_MissingDefaultBaselineIsEmpty(t *testing.T) {
	t.Chdir(t.TempDir()) // no .glsec-ignore here
	findings := []finding.Finding{{RuleID: "GL001", File: "a.yml", Line: 2, Message: "x"}}
	if got, err := filterNewOnly(io.Discard, findings, ""); err != nil || len(got) != 1 {
		t.Fatalf("missing default baseline should treat everything as new, got %d", len(got))
	}
}

// An expired entry accepts nothing, with or without --new-only (#1249).
func TestRun_NewOnlyExpiredEntry(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "build:\n  image: alpine:latest\n  script: [x]\n",
		".glsec-ignore":  ".gitlab-ci.yml:2 GL001 exp:2000-01-01\n",
	}
	code, stdout, stderr := runCLI(t, files, "--only", "GL001", "--no-cache", "--new-only", ".gitlab-ci.yml")
	if code != 1 || !strings.Contains(stdout, "GL001") {
		t.Fatalf("exit %d, want 1 with GL001; stdout:\n%s", code, stdout)
	}
	if !strings.Contains(stderr, ".gitlab-ci.yml:2: GL001 suppression has expired") {
		t.Errorf("no expiry note in stderr:\n%s", stderr)
	}

	files[".glsec-ignore"] = ".gitlab-ci.yml:2 GL001 exp:2999-01-01\n"
	if code, stdout, _ := runCLI(t, files, "--only", "GL001", "--no-cache", "--new-only", ".gitlab-ci.yml"); code != 0 {
		t.Errorf("an entry that hasn't expired: exit %d, stdout:\n%s", code, stdout)
	}
}
