// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/csv"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/glsec/glsec/internal/finding"
)

func templateFixture() ([]finding.Finding, []ScanError, TemplateMeta) {
	findings := []finding.Finding{
		{RuleID: "GL001", Severity: finding.Error, Job: "build", File: ".gitlab-ci.yml", Line: 3, Message: `image "node:latest" uses mutable tag "latest"`},
		{RuleID: "GL053", Severity: finding.Warn, File: ".gitlab-ci.yml", Line: 1, Message: "no top-level workflow:rules"},
		{RuleID: "GL070", Severity: finding.Info, Job: "@all", File: "ci/child.yml", Line: 5, Message: "see #1 and `make`"},
		{RuleID: "GL011", Severity: finding.Error, Job: "=HYPERLINK(\"http://x\")", File: ".gitlab-ci.yml", Line: 7, Message: "a|b <img src=x> *c* \"q\", d\nnext \u202eevil"},
	}
	errs := []ScanError{{File: "broken.yml", Message: "broken.yml: yaml: line 2: <bad> | input"}}
	meta := TemplateMeta{
		Version: "1.2.3",
		Files:   3,
		OWASP: func(id string) []string {
			if id == "GL001" {
				return []string{"CICD-SEC-3", "CICD-SEC-8"}
			}
			return nil
		},
	}
	return findings, errs, meta
}

// TestTemplateExamples renders the templates shipped under docs/templates and
// compares them with testdata. Regenerate after an intended change:
// go test ./internal/output -run TestTemplateExamples -update
func TestTemplateExamples(t *testing.T) {
	for _, c := range []struct{ tmpl, golden string }{
		{"csv.tmpl", "template-csv.golden.csv"},
		{"mr-comment.md.tmpl", "template-mr-comment.golden.md"},
	} {
		t.Run(c.tmpl, func(t *testing.T) {
			tmpl, err := ParseTemplate(filepath.Join("..", "..", "docs", "templates", c.tmpl))
			if err != nil {
				t.Fatal(err)
			}
			findings, errs, meta := templateFixture()
			var buf bytes.Buffer
			if err := Write(&buf, FormatTemplate, findings, 4, false, false, WithErrors(errs), WithTemplate(tmpl, meta)); err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", c.golden)
			if *updateGolden {
				if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden) //nolint:gosec // G304: the package's own golden file
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if got := buf.String(); got != string(want) {
				t.Errorf("output differs from %s (run with -update after an intended change)\ngot:\n%s", golden, got)
			}
		})
	}
}

// The CSV example has to stay valid CSV, one row per finding, with the
// values read back as escapeCSV wrote them.
func TestTemplateCSV_RoundTrip(t *testing.T) {
	tmpl, err := ParseTemplate(filepath.Join("..", "..", "docs", "templates", "csv.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	findings, _, meta := templateFixture()
	var buf bytes.Buffer
	if err := Write(&buf, FormatTemplate, findings, 4, false, false, WithTemplate(tmpl, meta)); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV: %v", err)
	}
	if len(rows) != len(findings)+1 {
		t.Fatalf("got %d rows, want %d", len(rows), len(findings)+1)
	}
	last := rows[len(rows)-1]
	if last[2] != "'"+findings[3].Job || last[5] != Sanitize(findings[3].Message) {
		t.Errorf("row = %q", last)
	}
}

func TestTemplate_Summary(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs).Parse(
		`{{.Version}} {{.Summary.Error}}/{{.Summary.Warn}}/{{.Summary.Info}} {{.Summary.Files}} {{.Summary.Jobs}} {{len .Errors}} {{range .Findings}}{{join .OWASP ","}}{{end}}`))
	findings, errs, meta := templateFixture()
	var buf bytes.Buffer
	if err := Write(&buf, FormatTemplate, findings, 4, false, false, WithErrors(errs), WithTemplate(tmpl, meta)); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "1.2.3 2/1/1 3 4 1 CICD-SEC-3,CICD-SEC-8"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestEscapeCSV(t *testing.T) {
	for in, want := range map[string]string{
		"":                `""`,
		"plain":           `"plain"`,
		`say "hi", ok`:    `"say ""hi"", ok"`,
		"=1+1":            `"'=1+1"`,
		"+1":              `"'+1"`,
		"-1":              `"'-1"`,
		"@SUM(A1)":        `"'@SUM(A1)"`,
		"\t=1":            `"\x09=1"`,
		"\r=1":            `"\x0d=1"`,
		"a=1":             `"a=1"`,
		"line\nbreak":     `"line\x0abreak"`,
		"a\u202eb":        `"a\u202eb"`,
		`=cmd|' /C calc'`: `"'=cmd|' /C calc'"`,
	} {
		if got := escapeCSV(in); got != want {
			t.Errorf("escapeCSV(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestEscapeMarkdown(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":         "plain text",
		"a|b":                `a\|b`,
		"<script>x</script>": "&lt;script&gt;x&lt;/script&gt;",
		`[link](http://x)`:   `\[link\](http://x)`,
		"*bold* _it_ `code`": "\\*bold\\* \\_it\\_ \\`code\\`",
		"line\nbreak":        `line\\x0abreak`,
		"a\u202eb":           `a\\u202eb`,
		`it's "q" & co`:      `it's "q" &amp; co`,
		`back\slash`:         `back\\slash`,
	} {
		if got := escapeMarkdown(in); got != want {
			t.Errorf("escapeMarkdown(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMarkdownCode(t *testing.T) {
	for in, want := range map[string]string{
		"":                   "",
		"build":              "` build `",
		"@all see #1":        "` @all see #1 `",
		"<script>x</script>": "` <script>x</script> `",
		"a|b":                "` a\\|b `",
		"run `make`":         "`` run `make` ``",
		"``x`":               "``` ``x` ```",
		"line\nbreak":        "` line\\x0abreak `",
	} {
		if got := markdownCode(in); got != want {
			t.Errorf("markdownCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEscapeXML(t *testing.T) {
	if got, want := escapeXML(`<a href="x">&'`+"\x01"), "&lt;a href=&#34;x&#34;&gt;&amp;&#39;�"; got != want {
		t.Errorf("escapeXML = %q, want %q", got, want)
	}
}

func TestParseTemplate_Errors(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.tmpl")
	if err := os.WriteFile(broken, []byte("{{range .Findings}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTemplate(broken); err == nil {
		t.Error("expected a parse error for an unclosed range")
	}
	if _, err := ParseTemplate(filepath.Join(dir, "missing.tmpl")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected a not-exist error, got %v", err)
	}
}

// A template that fails while executing writes nothing, not a partial report.
func TestWriteTemplate_ExecErrorWritesNothing(t *testing.T) {
	tmpl := template.Must(template.New("t").Parse(`header{{range .Findings}}{{.Nope}}{{end}}`))
	findings, _, meta := templateFixture()
	var buf bytes.Buffer
	err := Write(&buf, FormatTemplate, findings, 4, false, false, WithTemplate(tmpl, meta))
	if err == nil || !strings.Contains(err.Error(), "template:") {
		t.Fatalf("expected a template error, got %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("partial report written: %q", buf.String())
	}
}

func TestWriteTemplate_NoTemplate(t *testing.T) {
	if err := Write(&bytes.Buffer{}, FormatTemplate, nil, 0, false, false); err == nil {
		t.Error("expected an error for --format template without a template")
	}
}

func TestWriteTemplate_WriteError(t *testing.T) {
	tmpl := template.Must(template.New("t").Parse(`x`))
	if err := Write(&failAfter{}, FormatTemplate, nil, 0, false, false, WithTemplate(tmpl, TemplateMeta{})); !errors.Is(err, errWrite) {
		t.Errorf("expected the write error, got %v", err)
	}
}
