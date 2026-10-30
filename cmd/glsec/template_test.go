// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

const templatePipeline = "job:\n  image: node:latest\n  script: [make]\n"

func TestRun_TemplateFormat(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": templatePipeline,
		"report.tmpl":    "{{.Summary.Error}} {{.Summary.Files}} {{.Summary.Jobs}}{{range .Findings}} {{.Rule}}@{{.File}}:{{.Line}} {{join .OWASP \",\"}}{{end}}\n",
	}
	code, out, stderr := runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "template", "--template", "report.tmpl")
	if code != 1 || out != "1 1 1 GL001@.gitlab-ci.yml:2 CICD-SEC-3\n" {
		t.Fatalf("exit %d, output %q, stderr %s", code, out, stderr)
	}
}

// Secret values are masked in the template data as in every other format.
func TestRun_TemplateFormatMasks(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "job:\n  script:\n    - mysql -h db.example.com -psupersecret123 app\n",
		"report.tmpl":    "{{range .Findings}}{{.Rule}} {{.Message}}\n{{end}}",
	}
	_, out, stderr := runCLI(t, files, "--no-cache", "--only", "GL038", "--format", "template", "--template", "report.tmpl")
	if !strings.Contains(out, "GL038") || strings.Contains(out, "supersecret123") {
		t.Fatalf("secret in template output: %s (stderr %s)", out, stderr)
	}
}

func TestRun_TemplateFlagErrors(t *testing.T) {
	for _, tc := range []struct {
		name, tmpl string
		args       []string
		stderr     string
	}{
		{"template without format", "x", []string{"--template", "report.tmpl"}, "--template requires --format template"},
		{"format without template", "x", []string{"--format", "template"}, "--format template requires --template"},
		{"missing file", "x", []string{"--format", "template", "--template", "missing.tmpl"}, "--template:"},
		{"parse error", "{{range .Findings}}", []string{"--format", "template", "--template", "report.tmpl"}, "--template:"},
		{"execution error", "partial {{.Nope}}", []string{"--format", "template", "--template", "report.tmpl"}, "template:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{".gitlab-ci.yml": templatePipeline, "report.tmpl": tc.tmpl}
			code, out, stderr := runCLI(t, files, append([]string{"--no-cache"}, tc.args...)...)
			if code != 2 || out != "" || !strings.Contains(stderr, tc.stderr) {
				t.Fatalf("exit %d, output %q, stderr %q; want exit 2, no output, stderr with %q", code, out, stderr, tc.stderr)
			}
		})
	}
}

// The template comes from the command line only: .glsec.yml lives in the
// scanned repository, which must not choose what glsec writes in CI.
func TestRun_TemplateNotFromConfig(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": templatePipeline,
		".glsec.yml":     "template: report.tmpl\n",
		"report.tmpl":    "pwned\n",
	}
	code, out, stderr := runCLI(t, files, "--no-cache", "--format", "json")
	if code != 2 || strings.Contains(out, "pwned") {
		t.Fatalf("exit %d, output %q, stderr %s; want the config key rejected", code, out, stderr)
	}
}
