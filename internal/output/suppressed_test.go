// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func TestSuppressedSummary(t *testing.T) {
	open := []finding.Finding{{RuleID: "GL053", Severity: finding.Warn, File: "ci.yml", Line: 1, Message: "no workflow:rules"}}
	inline := finding.Suppressed{Finding: finding.Finding{RuleID: "GL001", Severity: finding.Error, File: "ci.yml", Line: 2}, Source: finding.SourceInline}
	ignored := finding.Suppressed{Finding: finding.Finding{RuleID: "GL016", Severity: finding.Warn, File: "ci.yml", Line: 3}, Source: finding.SourceIgnoreFile}
	for _, tc := range []struct {
		name       string
		format     Format
		findings   []finding.Finding
		suppressed []finding.Suppressed
		want       string
	}{
		{"text, both sources", FormatText, open, []finding.Suppressed{inline, ignored, inline},
			"\n3 findings suppressed (2 inline, 1 .glsec-ignore); run with --no-ignores to show them\n"},
		{"table, one", FormatTable, open, []finding.Suppressed{ignored},
			"\n1 finding suppressed (1 .glsec-ignore); run with --no-ignores to show them\n"},
		{"text, nothing open", FormatText, nil, []finding.Suppressed{inline},
			"1 finding suppressed (1 inline); run with --no-ignores to show them\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Write(&buf, tc.format, tc.findings, 1, false, false, WithSuppressed(tc.suppressed)); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); !strings.HasSuffix(got, tc.want) || strings.Count(got, "suppressed") != 1 {
				t.Errorf("output %q, want it to end with %q", got, tc.want)
			}
		})
	}
	for _, format := range []Format{FormatText, FormatTable} {
		var buf bytes.Buffer
		if err := Write(&buf, format, open, 1, false, false); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "suppressed") {
			t.Errorf("%s: summary without suppressed findings: %q", format, buf.String())
		}
	}
}

func TestSuppressedSummary_WriteError(t *testing.T) {
	s := []finding.Suppressed{{Finding: finding.Finding{RuleID: "GL001", File: "ci.yml", Line: 2}, Source: finding.SourceInline}}
	for _, format := range []Format{FormatText, FormatTable} {
		if err := Write(&failAfter{}, format, nil, 0, false, false, WithSuppressed(s)); !errors.Is(err, errWrite) {
			t.Errorf("%s: err = %v, want the write error", format, err)
		}
	}
}

// Suppressed findings go in their own array, so consumers of findings, and a
// snapshot used as --baseline, see what they saw before.
func TestWriteJSON_Suppressed(t *testing.T) {
	findings, _ := schemaFixture()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, findings[:1], func(string) []string { return []string{"CICD-SEC-3"} }, nil, WithSuppressed(suppressedFixture())); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Findings   []map[string]any `json:"findings"`
		Suppressed []map[string]any `json:"suppressed"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Findings) != 1 || len(out.Suppressed) != 2 {
		t.Fatalf("findings %d, suppressed %d; want 1 and 2", len(out.Findings), len(out.Suppressed))
	}
	first := out.Suppressed[0]
	if first["rule"] != "GL001" || first["line"] != float64(20) || first["owasp"] == nil {
		t.Errorf("suppressed entry lacks the finding fields: %v", first)
	}
	want := map[string]any{"source": "inline", "reason": "pinned by renovate", "expires": "2027-01-31"}
	if got := first["suppression"].(map[string]any); len(got) != len(want) || got["source"] != want["source"] || got["reason"] != want["reason"] || got["expires"] != want["expires"] {
		t.Errorf("suppression = %v, want %v", got, want)
	}
	if got := out.Suppressed[1]["suppression"].(map[string]any); len(got) != 1 || got["source"] != "ignore-file" {
		t.Errorf("suppression = %v, want only the source", got)
	}

	buf.Reset()
	if err := Write(&buf, FormatJSON, findings[:1], 1, false, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "suppressed") {
		t.Errorf("suppressed array without suppressed findings: %s", buf.String())
	}
}
