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

var testFindingsWithJob = []finding.Finding{
	{RuleID: "GL024", Severity: finding.Warn, Job: "phpmd", File: ".gitlab-ci.yml", Line: 52, Message: "script uses a pipe without set -o pipefail"},
	{RuleID: "GL024", Severity: finding.Warn, Job: "e2e", File: ".gitlab-ci.yml", Line: 170, Message: "script uses a pipe without set -o pipefail"},
	{RuleID: "GL001", Severity: finding.Error, File: ".gitlab-ci.yml", Line: 1, Message: `image "node:latest" uses mutable tag`},
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatText, testFindings, 5, false); err != nil {
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
	if err := Write(&buf, FormatText, nil, 7, false); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "7") || !strings.Contains(got, "0 issues found") {
		t.Errorf("expected summary line with job count, got %q", got)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatJSON, testFindings, 0, false); err != nil {
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
	if err := Write(&buf, FormatJSON, nil, 0, false); err != nil {
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
	if err := Write(&buf, FormatSARIF, testFindings, 0, false); err != nil {
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
	if err := Write(&buf, FormatText, testFindingsWithJob, 3, false); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "[phpmd]") {
		t.Errorf("expected [phpmd] in output: %q", got)
	}
	if !strings.Contains(got, "[e2e]") {
		t.Errorf("expected [e2e] in output: %q", got)
	}
	// Finding without a job should not contain brackets around a job name.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	last := lines[len(lines)-1]
	if strings.Contains(last, "[") && strings.Contains(last, "]") {
		t.Errorf("finding without job should not render brackets, got: %q", last)
	}
}

func TestWriteJSON_WithJob(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, FormatJSON, testFindingsWithJob, 0, false); err != nil {
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

func TestParseFormat(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Format
		ok   bool
	}{
		{"text", FormatText, true},
		{"json", FormatJSON, true},
		{"sarif", FormatSARIF, true},
		{"codeclimate", FormatCodeClimate, true},
		{"xml", "", false},
		{"", "", false},
	} {
		got, ok := ParseFormat(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("ParseFormat(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
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
	if err := WriteSARIF(&buf, testFindings, cweID, cweName, nil, nil); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	run := log.Runs[0]

	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule descriptor (GL001 has CWE, GL002 does not), got %d", len(run.Tool.Driver.Rules))
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
	if err := WriteSARIF(&buf, testFindings, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 0 {
		t.Error("expected no rule descriptors when CWE lookup is nil")
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
	if err := WriteJSON(&buf, testFindings, owasp); err != nil {
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
	if err := Write(&buf, FormatCodeClimate, testFindings, 0, false); err != nil {
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
	if err := Write(&buf, FormatCodeClimate, nil, 0, false); err != nil {
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
	if err := WriteSARIF(&buf, testFindings, nil, nil, owasp, owaspName); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected 1 rule descriptor (GL001 has OWASP, GL002 does not), got %d", len(run.Tool.Driver.Rules))
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
