// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// schemaFixture exercises every field the SARIF, Code Quality and JUnit
// writers fill: findings with and without a job, a column, a multi-line
// message, a path with spaces, a finding without a line, and scan errors with
// and without a file (#809).
func schemaFixture() ([]finding.Finding, []ScanError) {
	findings := []finding.Finding{
		{RuleID: "GL001", Severity: finding.Error, Job: "build", File: ".gitlab-ci.yml", Line: 3, Col: 5, Message: `image "node:latest" uses mutable tag "latest"`},
		{RuleID: "GL053", Severity: finding.Warn, File: ".gitlab-ci.yml", Line: 1, Message: "no top-level workflow:rules"},
		{RuleID: "GL011", Severity: finding.Error, Job: "deploy prod", File: "ci/my pipelines/deploy.yml", Line: 7, Message: "script pipes a download\ninto sh"},
		{RuleID: "GL070", Severity: finding.Info, Job: "lint", File: "ci/child.yml", Message: "informational"},
		{RuleID: "SC2086", Severity: finding.Warn, Job: "build", File: ".gitlab-ci.yml", Line: 12, Col: 9, Message: "Double quote to prevent globbing and word splitting."},
	}
	errs := []ScanError{
		{File: "ci/broken file.yml", Message: "parse ci/broken file.yml: yaml: line 2: did not find expected ',' or ']'"},
		{Message: "every file to scan matches exclude_paths or --exclude; nothing was scanned"},
	}
	return findings, errs
}

// suppressedFixture holds an inline suppression with a reason and an expiry
// and a .glsec-ignore entry, for a rule no open finding has (#834).
func suppressedFixture() []finding.Suppressed {
	return []finding.Suppressed{
		{Finding: finding.Finding{RuleID: "GL001", Severity: finding.Error, Job: "test", File: ".gitlab-ci.yml", Line: 20, Col: 5, Message: `image "ruby:latest" uses mutable tag "latest"`}, Source: finding.SourceInline, Reason: "pinned by renovate", Expires: "2027-01-31"},
		{Finding: finding.Finding{RuleID: "GL016", Severity: finding.Warn, Job: "docs", File: "ci/docs.yml", Line: 4, Message: "http:// URL"}, Source: finding.SourceIgnoreFile},
	}
}

// TestSchemaGoldenReports compares the reports with the golden files in
// testdata, which CI validates against each format's schema (#927): SARIF
// 2.1.0, the Code Quality fields GitLab documents, and a JUnit XSD. After an
// intended change: go test ./internal/output -run TestSchemaGoldenReports -update
func TestSchemaGoldenReports(t *testing.T) {
	findings, errs := schemaFixture()
	for _, tc := range []struct {
		golden string
		write  func(*bytes.Buffer) error
	}{
		{"sarif.golden.json", func(b *bytes.Buffer) error {
			return WriteSARIF(b, findings, SARIFTool{
				Version: "1.2.3",
				Rule: func(id string) SARIFRule {
					return map[string]SARIFRule{
						"GL001": {Title: "Mutable image tag", Risk: "Tags like latest move.", Details: "Checks `image:`.", Fix: "image: node:22.11.0", Severity: finding.Error},
						"GL011": {Title: "Download and execute", Risk: "Code runs unverified.", Fix: "script:\n  - sha256sum -c install.sh.sha256", Severity: finding.Error},
					}[id]
				},
			},
				func(id string) string { return map[string]string{"GL001": "CWE-1104", "GL011": "CWE-494"}[id] },
				func(cwe string) string {
					return map[string]string{"CWE-1104": "Use of Unmaintained Third Party Components", "CWE-494": "Download of Code Without Integrity Check"}[cwe]
				},
				func(id string) []string { return map[string][]string{"GL001": {"CICD-SEC-3"}}[id] },
				func(string) string { return "Dependency Chain Abuse" },
				func(id string) []string { return map[string][]string{"GL011": {"ASVS-V14.2.4"}}[id] },
				func(string) string { return "Verify the integrity of third-party components" },
				WithErrors(errs), WithSuppressed(suppressedFixture()))
		}},
		// Neither format has a suppressed state: the suppressed findings must
		// not show up as open issues or failed tests.
		{"codequality.golden.json", func(b *bytes.Buffer) error {
			return writeCodeQuality(b, findings, WithErrors(errs), WithSuppressed(suppressedFixture()))
		}},
		{"junit.golden.xml", func(b *bytes.Buffer) error {
			return Write(b, FormatJUnit, findings, 3, false, false, WithErrors(errs), WithSuppressed(suppressedFixture()))
		}},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.write(&buf); err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", tc.golden)
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
		})
	}
}
