package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

var testFindings = []finding.Finding{
	{RuleID: "GL001", Severity: finding.Error, File: "ci.yml", Line: 4, Message: `Mutable image tag "node:latest"`},
	{RuleID: "GL002", Severity: finding.Warn, File: "ci.yml", Line: 12, Message: "Unquoted variable $CI_COMMIT_REF_NAME"},
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, testFindings); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "ERROR") || !strings.Contains(got, "WARN") {
		t.Errorf("missing severity labels: %q", got)
	}
	if !strings.Contains(got, "GL001") || !strings.Contains(got, "GL002") {
		t.Errorf("missing rule IDs: %q", got)
	}
	if !strings.Contains(got, "ci.yml:4") {
		t.Errorf("missing file:line: %q", got)
	}
}

func TestWriteText_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, nil); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output for no findings, got %q", buf.String())
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatJSON, testFindings); err != nil {
		t.Fatal(err)
	}
	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out.Findings))
	}
	f := out.Findings[0]
	if f.Rule != "GL001" || f.Severity != "error" || f.File != "ci.yml" || f.Line != 4 {
		t.Errorf("unexpected first finding: %+v", f)
	}
}

func TestWriteJSON_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatJSON, nil); err != nil {
		t.Fatal(err)
	}
	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out.Findings) != 0 {
		t.Errorf("expected empty findings array, got %d", len(out.Findings))
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatSARIF, testFindings); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	results := log.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].RuleID != "GL001" || results[0].Level != "error" {
		t.Errorf("unexpected first result: %+v", results[0])
	}
	if results[1].Level != "warning" {
		t.Errorf("expected warning level for WARN, got %q", results[1].Level)
	}
	loc := results[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "ci.yml" || loc.Region.StartLine != 4 {
		t.Errorf("unexpected location: %+v", loc)
	}
}

func TestParseFormat(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Format
		ok   bool
	}{
		{"text", FormatText, true},
		{"json", FormatJSON, true},
		{"sarif", FormatSARIF, true},
		{"xml", "", false},
		{"", "", false},
	} {
		got, ok := ParseFormat(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("ParseFormat(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
