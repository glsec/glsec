// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

var testFindings = []finding.Finding{
	{RuleID: "GL001", Severity: finding.Error, File: "ci.yml", Line: 4, Message: `Mutable image tag "node:latest"`},
	{RuleID: "GL002", Severity: finding.Warn, File: "ci.yml", Line: 12, Message: "Unquoted variable $CI_COMMIT_REF_NAME"},
}

var testFindingsWithJob = []finding.Finding{
	{RuleID: "GL024", Severity: finding.Warn, Job: "phpmd", File: ".gitlab-ci.yml", Line: 52, Message: "script uses a pipe without set -o pipefail"},
	{RuleID: "GL024", Severity: finding.Warn, Job: "e2e", File: ".gitlab-ci.yml", Line: 170, Message: "script uses a pipe without set -o pipefail"},
	{RuleID: "GL001", Severity: finding.Error, File: ".gitlab-ci.yml", Line: 1, Message: `image "node:latest" uses mutable tag`},
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, testFindings, 5, false, false); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	// Compiler-style header: severity[rule]: message
	if !strings.Contains(got, "error[GL001]:") || !strings.Contains(got, "warn[GL002]:") {
		t.Errorf("missing severity[rule] headers: %q", got)
	}
	if !strings.Contains(got, "--> ci.yml:4") {
		t.Errorf("missing location line: %q", got)
	}
	// ci.yml does not exist on disk, so the source block is skipped rather than
	// erroring. The header must still be there.
	if strings.Contains(got, " | ") {
		t.Errorf("no source block expected for a missing file: %q", got)
	}
}

func TestWriteText_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, nil, 7, false, true); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "7") || !strings.Contains(got, "0 issues found") {
		t.Errorf("expected summary line with job count, got %q", got)
	}
}

func TestWriteText_EmptyNonTTY(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, nil, 7, false, false); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "" {
		t.Errorf("expected no summary line when not a TTY, got %q", got)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatJSON, testFindings, 0, false, false); err != nil {
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
	if err := Write(&buf, FormatJSON, nil, 0, false, false); err != nil {
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
	if err := Write(&buf, FormatSARIF, testFindings, 0, false, false); err != nil {
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

func TestWriteText_WithJob(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, testFindingsWithJob, 3, false, false); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "(job: phpmd)") || !strings.Contains(got, "(job: e2e)") {
		t.Errorf("expected job names on the location line: %q", got)
	}
	// The third finding has no job, so exactly two location lines carry one.
	if n := strings.Count(got, "(job: "); n != 2 {
		t.Errorf("expected 2 job annotations, got %d: %q", n, got)
	}
}

func TestWriteJSON_WithJob(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatJSON, testFindingsWithJob, 0, false, false); err != nil {
		t.Fatal(err)
	}
	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.Findings[0].Job != "phpmd" {
		t.Errorf("expected job=phpmd, got %q", out.Findings[0].Job)
	}
	if out.Findings[1].Job != "e2e" {
		t.Errorf("expected job=e2e, got %q", out.Findings[1].Job)
	}
	if out.Findings[2].Job != "" {
		t.Errorf("expected empty job for no-job finding, got %q", out.Findings[2].Job)
	}
}

func TestWriteJSON_BidiCharactersEscaped(t *testing.T) {
	bidi := []rune{
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069',
		'\u200e', '\u200f', '\u061c',
	}
	job := "job\u202etset"
	file := "\u2066file.yml"
	msg := "a\u202ab\u202bc\u202cd\u202de\u202ef\u2066g\u2067h\u2068i\u2069j\u200ek\u200fl\u061cm"
	var buf bytes.Buffer
	findings := []finding.Finding{
		{RuleID: "GL001", Severity: finding.Error, Job: job, File: file, Line: 1, Message: msg},
	}
	if err := Write(&buf, FormatJSON, findings, 0, false, false); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	for _, r := range bidi {
		if strings.ContainsRune(raw, r) {
			t.Errorf("raw JSON output contains bidi rune U+%04X", r)
		}
	}
	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
	f := out.Findings[0]
	if f.Job != job || f.File != file || f.Message != msg {
		t.Errorf("round trip changed values: got job=%q file=%q message=%q", f.Job, f.File, f.Message)
	}
}

func TestWriteSARIF_BidiCharactersEscaped(t *testing.T) {
	file := "\u2066file.yml"
	msg := "a\u202eb\u202cc\u2066d\u200ee\u061cf"
	var buf bytes.Buffer
	findings := []finding.Finding{
		{RuleID: "GL001", Severity: finding.Error, Job: "job\u202etset", File: file, Line: 1, Message: msg},
	}
	if err := Write(&buf, FormatSARIF, findings, 0, false, false); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	for _, r := range []rune{'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069', '\u200e', '\u200f', '\u061c'} {
		if strings.ContainsRune(raw, r) {
			t.Errorf("raw SARIF output contains bidi rune U+%04X", r)
		}
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	result := log.Runs[0].Results[0]
	uri, err := url.PathUnescape(result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	if err != nil || result.Message.Text != msg || uri != file {
		t.Errorf("round trip changed values: got message=%q file=%q (%v)", result.Message.Text, uri, err)
	}
}

func TestWriteCodeClimate_BidiCharactersEscaped(t *testing.T) {
	file := "\u2066file.yml"
	msg := "a\u202eb\u2066c\u200ed\u061ce"
	var buf bytes.Buffer
	findings := []finding.Finding{
		{RuleID: "GL001", Severity: finding.Error, Job: "job\u202etset", File: file, Line: 1, Message: msg},
	}
	if err := Write(&buf, FormatCodeClimate, findings, 0, false, false); err != nil {
		t.Fatal(err)
	}
	raw := buf.String()
	for _, r := range []rune{'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069', '\u200e', '\u200f', '\u061c'} {
		if strings.ContainsRune(raw, r) {
			t.Errorf("raw Code Climate output contains bidi rune U+%04X", r)
		}
	}
	var issues []codeClimateIssue
	if err := json.Unmarshal(buf.Bytes(), &issues); err != nil {
		t.Fatalf("invalid Code Climate JSON: %v", err)
	}
	if issues[0].Description != msg || issues[0].Location.Path != file {
		t.Errorf("round trip changed values: got description=%q path=%q", issues[0].Description, issues[0].Location.Path)
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatTable, testFindingsWithJob, 3, false, false); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{"SEVERITY", "RULE", "JOB", "FILE", "LINE", "MESSAGE", "GL024", "phpmd", ".gitlab-ci.yml"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q:\n%s", want, got)
		}
	}
	// A finding without a job renders a "-" placeholder, never an empty cell.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if !strings.Contains(lines[len(lines)-1], "-") {
		t.Errorf("expected job placeholder in no-job row, got: %q", lines[len(lines)-1])
	}
}

func TestWriteTable_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatTable, nil, 9, false, true); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "9") || !strings.Contains(got, "0 issues found") {
		t.Errorf("expected summary line on clean run, got %q", got)
	}
	if strings.Contains(got, "SEVERITY") {
		t.Errorf("did not expect a table header on a clean run, got %q", got)
	}
}

func TestWriteTable_EmptyNonTTY(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatTable, nil, 9, false, false); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "" {
		t.Errorf("expected no summary line when not a TTY, got %q", got)
	}
}

func TestWriteTable_Color(t *testing.T) {
	findings := append([]finding.Finding{
		{RuleID: "GL099", Severity: finding.Info, Job: "lint", File: ".gitlab-ci.yml", Line: 9, Message: "informational"},
	}, testFindingsWithJob...)

	var plain, colored bytes.Buffer
	if err := Write(&plain, FormatTable, findings, 3, false, false); err != nil {
		t.Fatal(err)
	}
	if err := Write(&colored, FormatTable, findings, 3, true, false); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(plain.String(), "\033[") {
		t.Errorf("expected no ANSI escapes with colour disabled:\n%s", plain.String())
	}
	got := colored.String()
	for _, want := range []string{"\033[31mERROR\033[0m  ", "\033[33mWARN\033[0m   ", "\nINFO   "} {
		if !strings.Contains(got, want) {
			t.Errorf("coloured table missing %q:\n%q", want, got)
		}
	}
	if strings.Count(got, "\033[") != 2*(len(findings)-1) {
		t.Errorf("expected only the ERROR and WARN cells to be coloured:\n%q", got)
	}
	// Columns line up only if the escapes come on top of the plain layout.
	stripped := strings.NewReplacer("\033[31m", "", "\033[33m", "", "\033[0m", "").Replace(got)
	if stripped != plain.String() {
		t.Errorf("coloured table is misaligned:\nplain:\n%s\nstripped:\n%s", plain.String(), stripped)
	}
}

func TestParseFormat(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Format
		ok   bool
	}{
		{"text", FormatText, true},
		{"table", FormatTable, true},
		{"json", FormatJSON, true},
		{"sarif", FormatSARIF, true},
		{"codeclimate", FormatCodeClimate, true},
		{"junit", FormatJUnit, true},
		{"xml", "", false},
		{"", "", false},
	} {
		got, ok := ParseFormat(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("ParseFormat(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestWriteJUnit(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatJUnit, testFindingsWithJob, 3, false, false); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var root junitTestsuites
	if err := xml.Unmarshal(buf.Bytes(), &root); err != nil {
		t.Fatalf("output is not valid XML: %v\n%s", err, buf.String())
	}
	if root.Tests != 3 || root.Failures != 3 {
		t.Errorf("root tests/failures = %d/%d, want 3/3", root.Tests, root.Failures)
	}
	if len(root.Suites) != 1 || len(root.Suites[0].Cases) != 3 {
		t.Fatalf("expected 1 suite with 3 cases, got %d suites", len(root.Suites))
	}
	c := root.Suites[0].Cases[0]
	if c.Failure == nil {
		t.Fatal("expected a failure element on the first case")
	}
	if !strings.Contains(c.Name, "GL024") || !strings.Contains(c.Name, "phpmd") {
		t.Errorf("case name %q should mention the rule and job", c.Name)
	}
	if c.Classname != ".gitlab-ci.yml:52" {
		t.Errorf("classname = %q, want .gitlab-ci.yml:52", c.Classname)
	}
}

func TestWriteJUnit_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatJUnit, nil, 4, false, false); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var root junitTestsuites
	if err := xml.Unmarshal(buf.Bytes(), &root); err != nil {
		t.Fatalf("output is not valid XML: %v", err)
	}
	if root.Failures != 0 {
		t.Errorf("clean run should report 0 failures, got %d", root.Failures)
	}
	if len(root.Suites) != 1 || len(root.Suites[0].Cases) != 1 || root.Suites[0].Cases[0].Failure != nil {
		t.Error("clean run should emit a single passing case")
	}
}

func TestWriteSARIF_WithCWE(t *testing.T) {
	cweID := func(id string) string {
		if id == "GL001" {
			return "CWE-1104"
		}
		return ""
	}
	cweName := func(id string) string {
		if id == "CWE-1104" {
			return "Use of Unmaintained Third-Party Components"
		}
		return ""
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, testFindings, SARIFTool{}, cweID, cweName, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	run := log.Runs[0]

	// Every rule gets a descriptor for its helpUri; only GL001 has a CWE.
	if len(run.Tool.Driver.Rules) != 2 || len(run.Tool.Driver.Rules[1].Relationships) != 0 {
		t.Fatalf("expected descriptors for GL001 and GL002, relationships only on GL001, got %+v", run.Tool.Driver.Rules)
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.ID != "GL001" {
		t.Errorf("expected rule GL001, got %q", rule.ID)
	}
	if len(rule.Relationships) != 1 || rule.Relationships[0].Target.ID != "CWE-1104" {
		t.Errorf("unexpected CWE relationship: %+v", rule.Relationships)
	}

	if len(run.Taxonomies) != 1 || run.Taxonomies[0].Name != "CWE" {
		t.Fatalf("expected CWE taxonomy, got %+v", run.Taxonomies)
	}
	if len(run.Taxonomies[0].Taxa) != 1 || run.Taxonomies[0].Taxa[0].ID != "CWE-1104" {
		t.Errorf("unexpected taxa: %+v", run.Taxonomies[0].Taxa)
	}
}

func TestWriteSARIF_NoCWE(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, testFindings, SARIFTool{}, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if len(r.Relationships) != 0 {
			t.Errorf("%s: expected no relationships when CWE lookup is nil, got %+v", r.ID, r.Relationships)
		}
	}
	if len(log.Runs[0].Taxonomies) != 0 {
		t.Error("expected no taxonomies when CWE lookup is nil")
	}
}

func TestWriteJSON_WithOWASP(t *testing.T) {
	owasp := func(id string) []string {
		if id == "GL001" {
			return []string{"CICD-SEC-3"}
		}
		return []string{"CICD-SEC-6"}
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, testFindings, owasp, nil); err != nil {
		t.Fatal(err)
	}
	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out.Findings[0].OWASP) != 1 || out.Findings[0].OWASP[0] != "CICD-SEC-3" {
		t.Errorf("unexpected OWASP for GL001: %v", out.Findings[0].OWASP)
	}
	if len(out.Findings[1].OWASP) != 1 || out.Findings[1].OWASP[0] != "CICD-SEC-6" {
		t.Errorf("unexpected OWASP for GL002: %v", out.Findings[1].OWASP)
	}
}

func TestWriteCodeClimate(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatCodeClimate, testFindings, 0, false, false); err != nil {
		t.Fatal(err)
	}
	var issues []codeClimateIssue
	if err := json.Unmarshal(buf.Bytes(), &issues); err != nil {
		t.Fatalf("invalid Code Climate JSON: %v", err)
	}
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}

	got := issues[0]
	if got.Type != "issue" {
		t.Errorf("expected type=issue, got %q", got.Type)
	}
	if got.CheckName != "GL001" {
		t.Errorf("expected check_name=GL001, got %q", got.CheckName)
	}
	if got.Description != testFindings[0].Message {
		t.Errorf("description mismatch: %q", got.Description)
	}
	if got.Severity != "critical" {
		t.Errorf("expected severity=critical for Error finding, got %q", got.Severity)
	}
	if len(got.Categories) != 1 || got.Categories[0] != "Security" {
		t.Errorf("expected categories=[Security], got %v", got.Categories)
	}
	if got.Location.Path != "ci.yml" || got.Location.Lines.Begin != 4 {
		t.Errorf("unexpected location: %+v", got.Location)
	}
	if len(got.Fingerprint) != 64 {
		t.Errorf("expected 64-char sha256 fingerprint, got %d chars", len(got.Fingerprint))
	}

	if issues[1].Severity != "major" {
		t.Errorf("expected severity=major for Warn finding, got %q", issues[1].Severity)
	}
}

func TestWriteCodeClimate_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatCodeClimate, nil, 0, false, false); err != nil {
		t.Fatal(err)
	}
	var issues []codeClimateIssue
	if err := json.Unmarshal(buf.Bytes(), &issues); err != nil {
		t.Fatalf("invalid Code Climate JSON: %v", err)
	}
	if len(issues) != 0 {
		t.Errorf("expected empty array, got %d", len(issues))
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "[") {
		t.Errorf("expected JSON array, got %q", buf.String())
	}
}

func TestWriteCodeClimate_FingerprintStable(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	if err := WriteCodeClimate(&buf1, testFindings); err != nil {
		t.Fatal(err)
	}
	if err := WriteCodeClimate(&buf2, testFindings); err != nil {
		t.Fatal(err)
	}
	if buf1.String() != buf2.String() {
		t.Error("two runs over identical findings produced different output (fingerprints not deterministic)")
	}
}

func TestWriteCodeClimate_FingerprintUnique(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCodeClimate(&buf, testFindingsWithJob); err != nil {
		t.Fatal(err)
	}
	var issues []codeClimateIssue
	if err := json.Unmarshal(buf.Bytes(), &issues); err != nil {
		t.Fatalf("invalid Code Climate JSON: %v", err)
	}
	seen := map[string]bool{}
	for _, issue := range issues {
		if seen[issue.Fingerprint] {
			t.Errorf("duplicate fingerprint %s — distinct findings collided", issue.Fingerprint)
		}
		seen[issue.Fingerprint] = true
	}
}

func TestSeverityToCodeClimate(t *testing.T) {
	for _, tc := range []struct {
		in   finding.Severity
		want string
	}{
		{finding.Error, "critical"},
		{finding.Warn, "major"},
		{finding.Info, "info"},
	} {
		if got := severityToCodeClimate(tc.in); got != tc.want {
			t.Errorf("severityToCodeClimate(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWriteSARIF_WithOWASP(t *testing.T) {
	owasp := func(id string) []string {
		if id == "GL001" {
			return []string{"CICD-SEC-3"}
		}
		return nil
	}
	owaspName := func(id string) string {
		if id == "CICD-SEC-3" {
			return "Dependency Chain Abuse"
		}
		return ""
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, testFindings, SARIFTool{}, nil, nil, owasp, owaspName, nil, nil); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 || len(run.Tool.Driver.Rules[1].Relationships) != 0 {
		t.Fatalf("expected descriptors for GL001 and GL002, relationships only on GL001, got %+v", run.Tool.Driver.Rules)
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.ID != "GL001" {
		t.Errorf("expected rule GL001, got %q", rule.ID)
	}
	if len(rule.Relationships) != 1 || rule.Relationships[0].Target.ID != "CICD-SEC-3" {
		t.Errorf("unexpected OWASP relationship: %+v", rule.Relationships)
	}
	if rule.Relationships[0].Target.ToolComponent.Name != "OWASP Top 10 CI/CD Security Risks" {
		t.Errorf("unexpected tool component name: %q", rule.Relationships[0].Target.ToolComponent.Name)
	}
	if len(run.Taxonomies) != 1 || run.Taxonomies[0].Name != "OWASP Top 10 CI/CD Security Risks" {
		t.Fatalf("expected OWASP taxonomy, got %+v", run.Taxonomies)
	}
	if len(run.Taxonomies[0].Taxa) != 1 || run.Taxonomies[0].Taxa[0].ID != "CICD-SEC-3" {
		t.Errorf("unexpected taxa: %+v", run.Taxonomies[0].Taxa)
	}
}

func TestWriteJSON_WithASVS(t *testing.T) {
	asvs := func(id string) []string {
		if id == "GL001" {
			return []string{"ASVS-V14.2.2"}
		}
		return nil
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, testFindings, nil, asvs); err != nil {
		t.Fatal(err)
	}
	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(out.Findings[0].ASVS) != 1 || out.Findings[0].ASVS[0] != "ASVS-V14.2.2" {
		t.Errorf("expected ASVS-V14.2.2 for GL001, got %v", out.Findings[0].ASVS)
	}
	if len(out.Findings[1].ASVS) != 0 {
		t.Errorf("expected no ASVS for GL002, got %v", out.Findings[1].ASVS)
	}
}

func TestWriteSARIF_WithASVS(t *testing.T) {
	asvs := func(id string) []string {
		if id == "GL001" {
			return []string{"ASVS-V14.2.2"}
		}
		return nil
	}
	asvsName := func(id string) string {
		if id == "ASVS-V14.2.2" {
			return "Verify that all components are up to date and pinned to a specific version"
		}
		return ""
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, testFindings, SARIFTool{}, nil, nil, nil, nil, asvs, asvsName); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	run := log.Runs[0]
	rule := run.Tool.Driver.Rules[0]
	if rule.ID != "GL001" || len(rule.Relationships) != 1 || rule.Relationships[0].Target.ID != "ASVS-V14.2.2" {
		t.Errorf("unexpected ASVS relationship: %+v", rule.Relationships)
	}
	if rule.Relationships[0].Target.ToolComponent.Name != "OWASP ASVS" {
		t.Errorf("unexpected tool component: %q", rule.Relationships[0].Target.ToolComponent.Name)
	}
	if len(run.Taxonomies) != 1 || run.Taxonomies[0].Name != "OWASP ASVS" || run.Taxonomies[0].Version != "4.0.3" {
		t.Fatalf("expected OWASP ASVS 4.0.3 taxonomy, got %+v", run.Taxonomies)
	}
}

// The source lines come from what was parsed, not the file read again: for
// stdin input with --stdin-filename the file on disk holds something else.
func TestWriteText_SourceFromSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitlab-ci.yml")
	if err := os.WriteFile(path, []byte("build:\n  script: [make clean]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := []finding.Finding{{RuleID: "GL001", Severity: finding.Error, File: path, Line: 2, Col: 10, Message: "mutable image tag"}}
	sources := map[string][]byte{path: []byte("build:\n  image: node:latest\n")}
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, f, 1, false, false, WithSources(sources)); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "2 |   image: node:latest") || strings.Contains(got, "make clean") {
		t.Errorf("source line not taken from the sources: %q", got)
	}
}

func TestWriteText_SourceContext(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.gitlab-ci.yml"
	content := "build:\n  image: node:latest\n  script: [make]\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	f := []finding.Finding{{
		RuleID: "GL001", Severity: finding.Error, File: path, Line: 2, Col: 10,
		Message: "mutable image tag",
	}}
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, f, 1, false, false); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	if !strings.Contains(got, "2 |   image: node:latest") {
		t.Errorf("expected the offending source line: %q", got)
	}
	// Verify alignment rather than a literal run of spaces: the caret must sit at
	// the same offset as column 10 of the source line, gutter included.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	srcIdx := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "2 | ") {
			srcIdx = i
			break
		}
	}
	if srcIdx < 0 || srcIdx+1 >= len(lines) {
		t.Fatalf("expected a source line followed by a caret line: %q", got)
	}
	caretAt := strings.IndexByte(lines[srcIdx+1], '^')
	if want := len("2 | ") + 10 - 1; caretAt != want {
		t.Errorf("caret at offset %d, want %d (column 10): %q", caretAt, want, got)
	}
	if !strings.Contains(got, "--> "+path+":2:10") {
		t.Errorf("expected location with column: %q", got)
	}
}

func TestWriteText_OutOfRangeLineDegrades(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/.gitlab-ci.yml"
	if err := os.WriteFile(path, []byte("build:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := []finding.Finding{{
		RuleID: "GL001", Severity: finding.Warn, File: path, Line: 99, Col: 3, Message: "x",
	}}
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, f, 1, false, false); err != nil {
		t.Fatalf("a line past the end of the file must not error: %v", err)
	}
	if !strings.Contains(buf.String(), "warn[GL001]:") {
		t.Errorf("header should still be printed: %q", buf.String())
	}
}

func TestCodeClimateFingerprint_SeparatorInFields(t *testing.T) {
	a := finding.Finding{RuleID: "GL001", File: "ci.yml", Job: "a|b", Message: "c", Line: 1}
	b := finding.Finding{RuleID: "GL001", File: "ci.yml", Job: "a", Message: "b|c", Line: 1}
	if codeClimateFingerprint(a) == codeClimateFingerprint(b) {
		t.Error("findings that differ only in where a | sits got the same fingerprint")
	}
}

func TestRuleURL(t *testing.T) {
	for id, want := range map[string]string{
		"GL001":  "https://glsec.github.io/rules/GL001/",
		"GL085":  "https://glsec.github.io/rules/GL085/",
		"SC2086": "https://www.shellcheck.net/wiki/SC2086",
		"GL1":    "",
		"gl001":  "",
		"SC86":   "",
		"":       "",
	} {
		if got := RuleURL(id); got != want {
			t.Errorf("RuleURL(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestWriteSARIF_HelpURI checks that every rule descriptor links to its page
// and the tool to the website (#718).
func TestWriteSARIF_HelpURI(t *testing.T) {
	findings := append([]finding.Finding{{RuleID: "SC2086", Severity: finding.Warn, File: "ci.yml", Line: 3, Message: "quote it"}}, testFindings...)
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, findings, SARIFTool{}, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	driver := log.Runs[0].Tool.Driver
	if driver.InformationURI != "https://glsec.github.io" {
		t.Errorf("informationUri = %q", driver.InformationURI)
	}
	seen := map[string]bool{}
	for _, r := range driver.Rules {
		if seen[r.ID] {
			t.Errorf("%s has two descriptors", r.ID)
		}
		seen[r.ID] = true
		if r.HelpURI != RuleURL(r.ID) || r.HelpURI == "" {
			t.Errorf("%s: helpUri = %q", r.ID, r.HelpURI)
		}
	}
	for _, f := range findings {
		if !seen[f.RuleID] {
			t.Errorf("%s has no descriptor", f.RuleID)
		}
	}
}

var errWrite = errors.New("disk full")

// failAfter accepts n writes, then fails every write after them.
type failAfter struct{ n int }

func (w *failAfter) Write(p []byte) (int, error) {
	if w.n == 0 {
		return 0, errWrite
	}
	w.n--
	return len(p), nil
}

// Every format returns the writer's error, whichever write fails: the test
// lets the 1st, 2nd, … write fail until the output fits in the successful ones.
func TestWrite_WriterErrors(t *testing.T) {
	src := filepath.Join(t.TempDir(), "ci.yml")
	if err := os.WriteFile(src, []byte("build:\n  image: node:latest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := []finding.Finding{
		{RuleID: "GL001", Severity: finding.Error, File: src, Line: 2, Col: 10, Job: "build", Message: "mutable tag"},
		{RuleID: "GL002", Severity: finding.Warn, File: src, Line: 1, Message: "second"},
	}
	for _, format := range []Format{FormatText, FormatTable, FormatJSON, FormatSARIF, FormatCodeClimate, FormatJUnit} {
		t.Run(string(format), func(t *testing.T) {
			failures := 0
			for n := 0; ; n++ {
				err := Write(&failAfter{n: n}, format, findings, 1, true, true)
				if err == nil {
					break
				}
				if !errors.Is(err, errWrite) {
					t.Fatalf("write %d: got %v, want the writer's error", n, err)
				}
				failures++
				if n > 100 {
					t.Fatal("output never fits")
				}
			}
			if failures == 0 {
				t.Error("no write failed")
			}
		})
	}
}

func TestWrite_CleanRunSummaryWriteError(t *testing.T) {
	for _, format := range []Format{FormatText, FormatTable} {
		if err := Write(&failAfter{}, format, nil, 3, false, true); !errors.Is(err, errWrite) {
			t.Errorf("%s: got %v, want the writer's error", format, err)
		}
	}
}

func TestWriteText_InfoAndNoColumn(t *testing.T) {
	src := filepath.Join(t.TempDir(), "ci.yml")
	if err := os.WriteFile(src, []byte("build:\n  script: [make]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	f := []finding.Finding{{RuleID: "GL099", Severity: finding.Info, File: src, Line: 2, Message: "note"}}
	if err := Write(&buf, FormatText, f, 1, true, false); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "info[") {
		t.Errorf("info severity must stay uncoloured: %q", got)
	}
	if !strings.Contains(got, "2 |   script: [make]") {
		t.Errorf("expected the source line: %q", got)
	}
	if strings.Contains(got, "^") {
		t.Errorf("column 0 must print no caret line: %q", got)
	}
}

func TestWriteSARIF_InfoAndRuleOnce(t *testing.T) {
	var buf bytes.Buffer
	f := []finding.Finding{
		{RuleID: "GL001", Severity: finding.Info, File: "a.yml", Line: 1, Message: "one"},
		{RuleID: "GL001", Severity: finding.Info, File: "b.yml", Line: 2, Message: "two"},
	}
	if err := WriteSARIF(&buf, f, SARIFTool{}, func(string) string { return "CWE-1104" }, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if len(run.Results) != 2 || run.Results[0].Level != "note" {
		t.Errorf("expected two results at level note, got %+v", run.Results)
	}
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("a rule with two findings must be listed once, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestWriteJUnit_LineZero(t *testing.T) {
	var buf bytes.Buffer
	f := []finding.Finding{{RuleID: "GL053", Severity: finding.Warn, File: ".gitlab-ci.yml", Message: "no workflow"}}
	if err := Write(&buf, FormatJUnit, f, 1, false, false); err != nil {
		t.Fatal(err)
	}
	var out junitTestsuites
	if err := xml.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	c := out.Suites[0].Cases[0]
	if c.Classname != ".gitlab-ci.yml" || !strings.HasSuffix(c.Failure.Text, " .gitlab-ci.yml") {
		t.Errorf("line 0 must not be appended to the location: %+v", c)
	}
}

func TestWriteSARIFRuleMetadata(t *testing.T) {
	tool := SARIFTool{
		Version: "1.24.1",
		Rule: func(id string) SARIFRule {
			return SARIFRule{
				Title:    "Mutable image tag",
				Risk:     "A tag can move.",
				Details:  "A tag can move:\n\n- latest\n- main",
				Fix:      "image: alpine:3.20.3",
				Severity: finding.Error,
			}
		},
	}
	var buf bytes.Buffer
	f := []finding.Finding{{RuleID: "GL001", Severity: finding.Warn, Message: "m", File: "x.yml", Line: 2}}
	if err := WriteSARIF(&buf, f, tool, func(string) string { return "CWE-1104" }, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Version, SemanticVersion string
					Rules                    []struct {
						ShortDescription     struct{ Text string }
						FullDescription      struct{ Text string }
						Help                 struct{ Text, Markdown string }
						DefaultConfiguration struct{ Level string }
						Properties           struct {
							Tags             []string
							SecuritySeverity string `json:"security-severity"`
						}
					}
				}
			}
			Results []struct{ Level string }
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	d := log.Runs[0].Tool.Driver
	r := d.Rules[0]
	switch {
	case d.Version != "1.24.1" || d.SemanticVersion != "1.24.1":
		t.Errorf("version = %q/%q", d.Version, d.SemanticVersion)
	case r.ShortDescription.Text != "Mutable image tag" || r.FullDescription.Text != "A tag can move.":
		t.Errorf("descriptions = %+v", r)
	case !strings.Contains(r.Help.Markdown, "- latest") || !strings.Contains(r.Help.Markdown, "```yaml\nimage: alpine:3.20.3\n```") || !strings.Contains(r.Help.Markdown, "(https://glsec.github.io/rules/GL001/)"):
		t.Errorf("help markdown = %q", r.Help.Markdown)
	case !strings.HasPrefix(r.Help.Text, "A tag can move.") || !strings.HasSuffix(r.Help.Text, "https://glsec.github.io/rules/GL001/"):
		t.Errorf("help text = %q", r.Help.Text)
	case r.DefaultConfiguration.Level != "error" || r.Properties.SecuritySeverity != "8.0":
		t.Errorf("level/severity = %q/%q", r.DefaultConfiguration.Level, r.Properties.SecuritySeverity)
	case strings.Join(r.Properties.Tags, ",") != "security,external/cwe/cwe-1104":
		t.Errorf("tags = %v", r.Properties.Tags)
	case log.Runs[0].Results[0].Level != "warning":
		t.Errorf("the result keeps the finding's own level, got %q", log.Runs[0].Results[0].Level)
	}
}

func TestWriteSARIFDevVersionLeftOut(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, testFindings, SARIFTool{Version: "dev"}, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `"version": "dev"`) || strings.Contains(buf.String(), "semanticVersion") {
		t.Errorf("dev version written: %s", buf.String()[:200])
	}
}

func TestSecuritySeverity(t *testing.T) {
	for s, want := range map[finding.Severity]string{finding.Error: "8.0", finding.Warn: "5.0", finding.Info: "2.0", "": ""} {
		if got := securitySeverity(s); got != want {
			t.Errorf("securitySeverity(%q) = %q, want %q", s, got, want)
		}
	}
}

// Without the doc section, the help markdown falls back to the description,
// and a rule with neither severity nor CWE still gets its security tag.
func TestDescribeSARIFRuleFallbacks(t *testing.T) {
	rule := sarifRule{ID: "GL001", HelpURI: RuleURL("GL001")}
	props := &sarifRuleProps{Tags: []string{"security"}}
	describeSARIFRule(&rule, SARIFRule{Risk: "A tag can move."}, props)
	if rule.Help == nil || !strings.HasPrefix(rule.Help.Markdown, "A tag can move.") || strings.Contains(rule.Help.Markdown, "Safe alternative") {
		t.Errorf("help = %+v", rule.Help)
	}
	if rule.DefaultConfiguration != nil || props.SecuritySeverity != "" {
		t.Errorf("severity set without one: %+v %+v", rule.DefaultConfiguration, props)
	}
	if rule.ShortDescription != nil {
		t.Errorf("title set without one: %+v", rule.ShortDescription)
	}
}
