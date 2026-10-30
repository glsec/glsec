// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const suppressedPipeline = "build:\n  image: node:latest # glsec:ignore GL001 exp:2999-12-31 -- pinned by renovate\n  script: [make]\n"

// A suppressed finding stays visible: a summary line in text, a result with
// suppressions in SARIF, an entry in JSON's suppressed array. It still
// doesn't fail the run (#834).
func TestRun_SuppressedInline(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": suppressedPipeline}
	code, out, stderr := runCLI(t, files, "--no-cache", "--only", "GL001")
	if code != 0 || !strings.Contains(out, "1 finding suppressed (1 inline); run with --no-ignores to show them") {
		t.Fatalf("text: exit %d, %q, stderr %s", code, out, stderr)
	}

	_, out, _ = runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "json")
	var report struct {
		Findings   []json.RawMessage `json:"findings"`
		Suppressed []struct {
			Rule        string `json:"rule"`
			Line        int    `json:"line"`
			Suppression struct {
				Source, Reason, Expires string
			} `json:"suppression"`
		} `json:"suppressed"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 0 || len(report.Suppressed) != 1 {
		t.Fatalf("json: %s", out)
	}
	if s := report.Suppressed[0]; s.Rule != "GL001" || s.Line != 2 || s.Suppression.Source != "inline" || s.Suppression.Reason != "pinned by renovate" || s.Suppression.Expires != "2999-12-31" {
		t.Errorf("json suppressed entry: %+v", s)
	}

	_, out, _ = runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "sarif")
	if !strings.Contains(out, `"kind": "inSource"`) || !strings.Contains(out, `"justification": "pinned by renovate"`) {
		t.Errorf("sarif: %s", out)
	}

	for _, format := range []string{"codeclimate", "junit", "gitlab-sast"} {
		_, out, _ = runCLI(t, files, "--no-cache", "--only", "GL001", "--format", format)
		if strings.Contains(out, "GL001") {
			t.Errorf("%s reports the suppressed finding as open: %s", format, out)
		}
	}
}

func TestRun_SuppressedIgnoreFile(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "build:\n  image: node:latest\n  script: [make]\n",
		".glsec-ignore":  ".gitlab-ci.yml:2 GL001\n",
	}
	code, out, stderr := runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "table")
	if code != 0 || !strings.Contains(out, "1 finding suppressed (1 .glsec-ignore)") {
		t.Fatalf("table: exit %d, %q, stderr %s", code, out, stderr)
	}
	_, out, _ = runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "sarif")
	if !strings.Contains(out, `"kind": "external"`) {
		t.Errorf("sarif: %s", out)
	}
	_, out, _ = runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "json")
	if !strings.Contains(out, `"source": "ignore-file"`) {
		t.Errorf("json: %s", out)
	}
}

// An expired suppression reports the finding, as before, and lists nothing as
// suppressed.
func TestRun_SuppressedExpired(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": "build:\n  image: node:latest # glsec:ignore GL001 exp:2000-01-01 -- old\n  script: [make]\n"}
	code, out, stderr := runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "json")
	if code != 1 || !strings.Contains(out, `"rule": "GL001"`) || strings.Contains(out, `"suppressed"`) {
		t.Fatalf("exit %d, %s, stderr %s", code, out, stderr)
	}
}

// --no-ignores reports everything as open, so nothing is suppressed.
func TestRun_SuppressedNoIgnores(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": suppressedPipeline}
	code, out, _ := runCLI(t, files, "--no-cache", "--no-ignores", "--only", "GL001")
	if code != 1 || strings.Contains(out, "suppressed") {
		t.Fatalf("exit %d, %q", code, out)
	}
}

// Secrets are masked in suppressed findings as in open ones (#831).
func TestRun_SuppressedMasked(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": "build:\n  script:\n    - mysql -h db.example.com -psupersecret123 app # glsec:ignore GL038 -- test db\n"}
	_, out, _ := runCLI(t, files, "--no-cache", "--only", "GL038", "--format", "json")
	if !strings.Contains(out, `"suppressed"`) || strings.Contains(out, "supersecret123") {
		t.Fatalf("json: %s", out)
	}
}

// A JSON snapshot with suppressed entries still works as --baseline: they are
// not baseline entries, so a finding that was suppressed is new once it isn't.
func TestRun_SuppressedBaselineSnapshot(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": suppressedPipeline}
	_, snapshot, _ := runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "json")
	setupCLI(t, map[string]string{
		".gitlab-ci.yml": "build:\n  image: node:latest\n  script: [make]\n",
		"base.json":      snapshot,
	})
	var out, stderr bytes.Buffer
	if code := run([]string{"--only", "GL001", "--baseline", "base.json", "--format", "json"}, &out, &stderr); code != 1 || !strings.Contains(out.String(), `"rule": "GL001"`) {
		t.Fatalf("exit %d, %s, stderr %s", code, &out, &stderr)
	}
}

// A cache hit keeps the suppressed findings.
func TestRun_SuppressedCached(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": suppressedPipeline}
	setupCLI(t, files)
	for i := range 2 {
		var out, stderr bytes.Buffer
		run([]string{"--cache", "--only", "GL001"}, &out, &stderr)
		if !strings.Contains(out.String(), "1 finding suppressed") {
			t.Fatalf("run %d: %q", i, &out)
		}
	}
}
