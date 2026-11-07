// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
)

func TestRun_PolicyViolationInReports(t *testing.T) {
	const src = "job:\n  image: node:latest # glsec:ignore GL001\n  script: [echo hi]\n"
	const complaint = ".gitlab-ci.yml:2: GL001 is suppressed without a reason"
	for _, format := range []string{"json", "sarif", "codeclimate", "junit", "gitlab-sast", "template"} {
		t.Run(format, func(t *testing.T) {
			files := map[string]string{".gitlab-ci.yml": src}
			args := []string{"--no-cache", "--only", "GL001", "--require-ignore-reason", "--format", format}
			if format == "template" {
				files["errors.tmpl"] = "{{range .Errors}}{{.File}} {{.Message}}{{end}}|{{len .Findings}}"
				args = append(args, "--template", "errors.tmpl")
			}
			code, out, stderr := runCLI(t, files, args...)
			if code != 2 || !strings.Contains(stderr, complaint) || !strings.Contains(stderr, "1 suppression(s) without a reason") {
				t.Fatalf("exit %d, stdout %s, stderr %s; want detailed policy error", code, out, stderr)
			}
			if !strings.Contains(out, complaint) {
				t.Fatalf("policy error missing from %s report: %s", format, out)
			}
			switch format {
			case "json":
				var report struct {
					Findings   []json.RawMessage
					Suppressed []json.RawMessage
					Errors     []struct{ File, Message string }
				}
				if err := json.Unmarshal([]byte(out), &report); err != nil {
					t.Fatal(err)
				}
				if len(report.Findings) != 0 || len(report.Suppressed) != 1 || len(report.Errors) != 1 || report.Errors[0].File != ".gitlab-ci.yml" {
					t.Fatalf("invalid policy report: %s", out)
				}
			case "sarif":
				var report struct {
					Runs []struct {
						Invocations []struct {
							ExecutionSuccessful        bool
							ToolExecutionNotifications []struct{ Level string }
						}
						Results []struct{ Suppressions []json.RawMessage }
					}
				}
				if err := json.Unmarshal([]byte(out), &report); err != nil {
					t.Fatal(err)
				}
				if len(report.Runs) != 1 {
					t.Fatalf("missing run: %s", out)
				}
				run := report.Runs[0]
				if len(run.Invocations) != 1 || run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].ToolExecutionNotifications) != 1 || run.Invocations[0].ToolExecutionNotifications[0].Level != "error" || len(run.Results) != 1 || len(run.Results[0].Suppressions) != 1 {
					t.Fatalf("invalid policy report: %s", out)
				}
			case "codeclimate":
				var issues []struct {
					CheckName string `json:"check_name"`
					Severity  string
				}
				if err := json.Unmarshal([]byte(out), &issues); err != nil {
					t.Fatal(err)
				}
				if len(issues) != 1 || issues[0].CheckName != "glsec-error" || issues[0].Severity != "blocker" {
					t.Fatalf("invalid policy report: %s", out)
				}
			case "junit":
				var report struct {
					Errors int `xml:"errors,attr"`
					Suites []struct {
						Errors int `xml:"errors,attr"`
						Cases  []struct {
							Error *struct {
								Message string `xml:"message,attr"`
							} `xml:"error"`
						} `xml:"testcase"`
					} `xml:"testsuite"`
				}
				if err := xml.Unmarshal([]byte(out), &report); err != nil {
					t.Fatal(err)
				}
				if report.Errors != 1 || len(report.Suites) != 1 || report.Suites[0].Errors != 1 || len(report.Suites[0].Cases) != 1 || report.Suites[0].Cases[0].Error == nil {
					t.Fatalf("invalid policy report: %s", out)
				}
			case "gitlab-sast":
				var report struct {
					Vulnerabilities []json.RawMessage
					Scan            struct {
						Status   string
						Messages []struct{ Level string }
					}
				}
				if err := json.Unmarshal([]byte(out), &report); err != nil {
					t.Fatal(err)
				}
				if report.Scan.Status != "failure" || len(report.Scan.Messages) != 1 || report.Scan.Messages[0].Level != "fatal" || len(report.Vulnerabilities) != 0 {
					t.Fatalf("invalid policy report: %s", out)
				}
			case "template":
				if !strings.HasSuffix(out, "|0") {
					t.Fatalf("suppressed finding became open: %s", out)
				}
			}
		})
	}
}

func TestRun_SharedFilePolicyErrorIsReportedOnce(t *testing.T) {
	files := map[string]string{
		"root.yml":   twoChildren("a", "b"),
		"a.yml":      "include: shared.yml\n",
		"b.yml":      "include: shared.yml\n",
		"shared.yml": "job:\n  image: node:latest # glsec:ignore GL001\n  script: [echo hi]\n",
	}
	code, out, stderr := runCLI(t, files, "--no-cache", "--only", "GL001", "--require-ignore-reason", "--format", "json", "root.yml")
	var report struct {
		Errors []struct{ File, Message string }
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if code != 2 || len(report.Errors) != 1 || report.Errors[0].File != "shared.yml" || !strings.Contains(report.Errors[0].Message, "shared.yml:2: GL001") || !strings.Contains(stderr, "1 suppression(s) without a reason") {
		t.Fatalf("exit %d, stdout %s, stderr %s", code, out, stderr)
	}
}
