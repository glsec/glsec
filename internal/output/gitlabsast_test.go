// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/finding"
)

var updateGolden = flag.Bool("update", false, "rewrite the testdata golden files")

func gitlabSASTFixture() ([]finding.Finding, GitLabSASTMeta) {
	findings := []finding.Finding{
		{RuleID: "GL001", Severity: finding.Error, Job: "build", File: ".gitlab-ci.yml", Line: 3, Message: `image "node:latest" uses mutable tag "latest"`},
		{RuleID: "GL053", Severity: finding.Warn, File: ".gitlab-ci.yml", Line: 1, Message: "no top-level workflow:rules"},
		{RuleID: "GL070", Severity: finding.Info, Job: "lint", File: "ci/child.yml", Line: 0, Message: "informational"},
		{RuleID: "SC2086", Severity: finding.Warn, Job: "deploy", File: ".gitlab-ci.yml", Line: 12, Message: "Double quote to prevent globbing and word splitting."},
		{RuleID: "GL011", Severity: finding.Error, Job: "a\u202eb", File: ".gitlab-ci.yml", Line: 7, Message: "pipe\nto sh"},
	}
	meta := GitLabSASTMeta{
		Version: "1.2.3",
		Rule: func(id string) SARIFRule {
			return map[string]SARIFRule{"GL001": {Title: "Mutable image tag"}, "GL011": {Title: "Download and execute"}}[id]
		},
		CWE: func(id string) string { return map[string]string{"GL001": "CWE-1104", "GL011": "CWE-494"}[id] },
		OWASP: func(id string) []string {
			return map[string][]string{"GL001": {"CICD-SEC-3"}, "GL053": {"CICD-SEC-1", "CICD-SEC-4"}}[id]
		},
		OWASPName: func(c string) string { return map[string]string{"CICD-SEC-3": "Dependency Chain Abuse"}[c] },
		Start:     time.Date(2026, 10, 28, 9, 30, 0, 0, time.FixedZone("CET", 3600)),
	}
	return findings, meta
}

// TestWriteGitLabSAST compares the report with testdata/gitlab-sast.golden.json,
// which CI also validates against GitLab's SAST report schema (#846). After an
// intended change: go test ./internal/output -run TestWriteGitLabSAST -update
func TestWriteGitLabSAST(t *testing.T) {
	findings, meta := gitlabSASTFixture()
	var buf bytes.Buffer
	if err := WriteGitLabSAST(&buf, findings, meta); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "gitlab-sast.golden.json")
	if *updateGolden {
		if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) //nolint:gosec // G304: the package's own golden file
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got := buf.String(); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("report differs from %s (run with -update after an intended change)\ngot:\n%s", golden, got)
	}
}

func TestWriteGitLabSAST_Fields(t *testing.T) {
	findings, meta := gitlabSASTFixture()
	var buf bytes.Buffer
	if err := WriteGitLabSAST(&buf, findings, meta); err != nil {
		t.Fatal(err)
	}
	var r gitlabSASTReport
	if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Version != GitLabSASTSchemaVersion || r.Scan.Type != "sast" || r.Scan.Status != "success" {
		t.Errorf("header = %q %q %q", r.Version, r.Scan.Type, r.Scan.Status)
	}
	if r.Scan.StartTime != "2026-10-28T08:30:00" || r.Scan.EndTime != r.Scan.StartTime {
		t.Errorf("times = %q, %q; want UTC without zone", r.Scan.StartTime, r.Scan.EndTime)
	}
	if r.Scan.Analyzer.Version != "1.2.3" || r.Scan.Scanner.ID != "glsec" {
		t.Errorf("tool = %+v", r.Scan.Analyzer)
	}
	v := r.Vulnerabilities
	if len(v) != len(findings) {
		t.Fatalf("%d vulnerabilities, want %d", len(v), len(findings))
	}
	if v[0].Name != "GL001: Mutable image tag" || v[0].Severity != "High" || v[0].Description != `image "node:latest" uses mutable tag "latest" (job: build)` {
		t.Errorf("GL001 = %+v", v[0])
	}
	if got := v[0].Identifiers; len(got) != 3 || got[0].Type != "glsec_rule" || got[1].Value != "1104" || got[2].Name != "CICD-SEC-3 Dependency Chain Abuse" {
		t.Errorf("GL001 identifiers = %+v", got)
	}
	if v[1].Name != "GL053" || v[1].Severity != "Medium" || len(v[1].Identifiers) != 3 {
		t.Errorf("GL053 without title = %+v", v[1])
	}
	if v[2].Severity != "Low" || v[2].Location.StartLine != 1 {
		t.Errorf("info finding on line 0 = %+v", v[2])
	}
	if v[3].Identifiers[0].URL != "https://www.shellcheck.net/wiki/SC2086" {
		t.Errorf("ShellCheck identifier = %+v", v[3].Identifiers[0])
	}
	if strings.ContainsAny(v[4].Description, "\n\u202e") || !strings.Contains(v[4].Description, "\\u202e") {
		t.Errorf("control and bidi characters not escaped: %q", v[4].Description)
	}
	seen := map[string]bool{}
	for _, x := range v {
		if seen[x.ID] || len(x.ID) != 36 || x.ID[14] != '5' {
			t.Errorf("ID %q not a unique UUID", x.ID)
		}
		seen[x.ID] = true
	}
	var again bytes.Buffer
	_ = WriteGitLabSAST(&again, findings, meta)
	if again.String() != buf.String() {
		t.Error("report not deterministic")
	}
}

func TestWriteGitLabSAST_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitLabSAST(&buf, nil, GitLabSASTMeta{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"vulnerabilities": []`) || !strings.Contains(buf.String(), `"version": "dev"`) {
		t.Errorf("empty report = %s", buf.String())
	}
}

func TestWrite_GitLabSAST(t *testing.T) {
	if f, ok := ParseFormat("gitlab-sast"); !ok || f != FormatGitLabSAST {
		t.Fatalf("ParseFormat(gitlab-sast) = %q, %v", f, ok)
	}
	var buf bytes.Buffer
	if err := Write(&buf, FormatGitLabSAST, []finding.Finding{{RuleID: "GL001", Severity: finding.Warn, File: "x.yml", Line: 2}}, 1, false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"type": "sast"`) {
		t.Errorf("Write = %s", buf.String())
	}
}
