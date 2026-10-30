// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"strings"
	"testing"
)

var testErrors = []ScanError{
	{File: "broken.yml", Message: "parse broken.yml: yaml: line 2: did not find expected ',' or ']'"},
	{Message: "every file to scan matches exclude_paths or --exclude; nothing was scanned"},
}

func writeWithErrors(t *testing.T, format Format, errs []ScanError) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, format, testFindings, 2, false, false, WithErrors(errs)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScanErrors_JSON(t *testing.T) {
	var got jsonOutput
	if err := json.Unmarshal(writeWithErrors(t, FormatJSON, testErrors), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != len(testFindings) {
		t.Errorf("findings = %d, want %d", len(got.Findings), len(testFindings))
	}
	want := []jsonError{{File: "broken.yml", Message: testErrors[0].Message}, {Message: testErrors[1].Message}}
	if len(got.Errors) != 2 || got.Errors[0] != want[0] || got.Errors[1] != want[1] {
		t.Errorf("errors = %+v, want %+v", got.Errors, want)
	}

	if clean := writeWithErrors(t, FormatJSON, nil); bytes.Contains(clean, []byte(`"errors"`)) {
		t.Errorf("a report without scan errors has an errors field:\n%s", clean)
	}
}

func TestScanErrors_CodeClimate(t *testing.T) {
	var got []codeClimateIssue
	if err := json.Unmarshal(writeWithErrors(t, FormatCodeClimate, testErrors), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(testFindings)+2 {
		t.Fatalf("issues = %d, want %d", len(got), len(testFindings)+2)
	}
	for i, wantPath := range []string{"broken.yml", "."} {
		issue := got[len(testFindings)+i]
		if issue.CheckName != "glsec-error" || issue.Severity != "blocker" || issue.Location.Path != wantPath || issue.Location.Lines.Begin != 1 {
			t.Errorf("error issue = %+v", issue)
		}
		if !strings.Contains(issue.Description, testErrors[i].Message) {
			t.Errorf("description %q lacks the error", issue.Description)
		}
		if len(issue.Fingerprint) != 64 {
			t.Errorf("fingerprint %q", issue.Fingerprint)
		}
	}
	if got[len(testFindings)].Fingerprint == got[len(testFindings)+1].Fingerprint {
		t.Error("two errors share a fingerprint")
	}
}

func TestScanErrors_SARIF(t *testing.T) {
	var got sarifLog
	if err := json.Unmarshal(writeWithErrors(t, FormatSARIF, testErrors), &got); err != nil {
		t.Fatal(err)
	}
	run := got.Runs[0]
	if len(run.Results) != len(testFindings) {
		t.Errorf("results = %d, want %d", len(run.Results), len(testFindings))
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("invocations = %+v, want one unsuccessful", run.Invocations)
	}
	n := run.Invocations[0].ToolExecutionNotifications
	if len(n) != 2 || n[0].Level != "error" || n[0].Message.Text != testErrors[0].Message {
		t.Fatalf("notifications = %+v", n)
	}
	loc := n[0].Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "broken.yml" || loc.ArtifactLocation.URIBaseID != "%SRCROOT%" || loc.Region != nil {
		t.Errorf("location = %+v, want broken.yml without a region", loc)
	}
	if len(n[1].Locations) != 0 {
		t.Errorf("an error without a file has locations: %+v", n[1].Locations)
	}

	if clean := writeWithErrors(t, FormatSARIF, nil); bytes.Contains(clean, []byte(`"invocations"`)) {
		t.Errorf("a report without scan errors has invocations:\n%s", clean)
	}
}

func TestScanErrors_SARIFAbsolutePathOutsideCwd(t *testing.T) {
	t.Chdir(t.TempDir())
	outside, err := filepath.Abs(filepath.Join("..", "elsewhere", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var got sarifLog
	if err := json.Unmarshal(writeWithErrors(t, FormatSARIF, []ScanError{{File: outside, Message: "boom"}}), &got); err != nil {
		t.Fatal(err)
	}
	loc := got.Runs[0].Invocations[0].ToolExecutionNotifications[0].Locations[0].PhysicalLocation.ArtifactLocation
	if loc.URIBaseID != "" {
		t.Errorf("location = %+v, want no %%SRCROOT%% for a file outside the working directory", loc)
	}
}

func TestScanErrors_JUnit(t *testing.T) {
	var got junitTestsuites
	if err := xml.Unmarshal(writeWithErrors(t, FormatJUnit, testErrors), &got); err != nil {
		t.Fatal(err)
	}
	suite := got.Suites[0]
	if got.Errors != 2 || suite.Errors != 2 || suite.Failures != len(testFindings) || suite.Tests != len(testFindings)+2 {
		t.Errorf("counts: root errors=%d, suite tests=%d failures=%d errors=%d", got.Errors, suite.Tests, suite.Failures, suite.Errors)
	}
	errCase := suite.Cases[len(testFindings)]
	if errCase.Error == nil || errCase.Error.Message != testErrors[0].Message || errCase.Classname != "broken.yml" {
		t.Errorf("error case = %+v", errCase)
	}

	var onlyErrors bytes.Buffer
	if err := Write(&onlyErrors, FormatJUnit, nil, 0, false, false, WithErrors(testErrors[:1])); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(onlyErrors.String(), "no findings") {
		t.Errorf("a failed scan reports a passing test case:\n%s", onlyErrors.String())
	}
}

func TestScanErrors_GitLabSAST(t *testing.T) {
	var got gitlabSASTReport
	if err := json.Unmarshal(writeWithErrors(t, FormatGitLabSAST, testErrors), &got); err != nil {
		t.Fatal(err)
	}
	if got.Scan.Status != "failure" {
		t.Errorf("status = %q, want failure", got.Scan.Status)
	}
	want := []gitlabSASTMessage{{Level: "fatal", Value: testErrors[0].Message}, {Level: "fatal", Value: testErrors[1].Message}}
	if len(got.Scan.Messages) != 2 || got.Scan.Messages[0] != want[0] || got.Scan.Messages[1] != want[1] {
		t.Errorf("messages = %+v, want %+v", got.Scan.Messages, want)
	}
	if len(got.Vulnerabilities) != len(testFindings) {
		t.Errorf("vulnerabilities = %d, want %d", len(got.Vulnerabilities), len(testFindings))
	}

	var clean gitlabSASTReport
	if err := json.Unmarshal(writeWithErrors(t, FormatGitLabSAST, nil), &clean); err != nil {
		t.Fatal(err)
	}
	if clean.Scan.Status != "success" || clean.Scan.Messages != nil {
		t.Errorf("clean scan = %+v", clean.Scan)
	}
}

func TestScanErrors_AbsolutePathIsRelative(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	abs := filepath.Join(dir, "ci", "broken.yml")
	errs := []ScanError{{File: abs, Message: "parse " + abs + ": yaml: line 2"}}
	for _, format := range []Format{FormatJSON, FormatCodeClimate, FormatSARIF, FormatJUnit, FormatGitLabSAST} {
		got := writeWithErrors(t, format, errs)
		if bytes.Contains(got, []byte(filepath.ToSlash(dir))) || bytes.Contains(got, []byte(strings.ReplaceAll(dir, `\`, `\\`))) {
			t.Errorf("%s report names the working directory:\n%s", format, got)
		}
		if !bytes.Contains(got, []byte("parse ci/broken.yml: yaml")) {
			t.Errorf("%s report lacks the relative path in the message:\n%s", format, got)
		}
	}
}
