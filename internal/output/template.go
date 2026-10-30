// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/glsec/glsec/internal/finding"
)

// TemplateMeta is what a template report needs beyond the findings (#829).
type TemplateMeta struct {
	Version     string
	Files       int
	OWASP, ASVS func(string) []string
}

// WithTemplate renders --format template with t.
func WithTemplate(t *template.Template, meta TemplateMeta) WriteOption {
	return func(c *writeConfig) {
		c.template = t
		c.templateMeta = meta
	}
}

// templateData is the data a template is executed with. Findings and Errors
// carry the same fields as the JSON report.
type templateData struct {
	Findings []jsonFinding
	Errors   []jsonError
	Summary  templateSummary
	Version  string
}

type templateSummary struct {
	Error, Warn, Info int
	Files, Jobs       int
}

// templateFuncs is deliberately small: case and join helpers, and one escape
// per output syntax, because finding messages carry text from the scanned file.
var templateFuncs = template.FuncMap{
	"upper":          strings.ToUpper,
	"lower":          strings.ToLower,
	"join":           strings.Join,
	"escapeCSV":      escapeCSV,
	"escapeMarkdown": escapeMarkdown,
	"markdownCode":   markdownCode,
	"escapeXML":      escapeXML,
}

// ParseTemplate reads and parses a --template file.
func ParseTemplate(path string) (*template.Template, error) {
	src, err := os.ReadFile(path) //nolint:gosec // G304: the path is a command-line argument, never from .glsec.yml
	if err != nil {
		return nil, err
	}
	return template.New(filepath.Base(path)).Funcs(templateFuncs).Parse(string(src))
}

// writeTemplate executes t into a buffer first, so a template that fails
// halfway writes no partial report.
func writeTemplate(w io.Writer, t *template.Template, findings []finding.Finding, errs []ScanError, jobCount int, meta TemplateMeta) error {
	data := templateData{
		Findings: jsonFindings(findings, meta.OWASP, meta.ASVS),
		Errors:   jsonErrors(errs),
		Summary:  templateSummary{Files: meta.Files, Jobs: jobCount},
		Version:  meta.Version,
	}
	for _, f := range findings {
		switch f.Severity {
		case finding.Error:
			data.Summary.Error++
		case finding.Warn:
			data.Summary.Warn++
		case finding.Info:
			data.Summary.Info++
		}
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return fmt.Errorf("template: %w", err)
	}
	_, err := buf.WriteTo(w)
	return err
}

// escapeCSV returns s as a quoted CSV field. Control and bidi characters are
// shown escaped as in the text output. A field that starts with a formula
// prefix gets a leading apostrophe, so a spreadsheet shows it as text instead
// of evaluating it (CSV injection).
func escapeCSV(s string) string {
	s = Sanitize(s)
	if s != "" && strings.ContainsRune("=+-@", rune(s[0])) {
		s = "'" + s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

var markdownReplacer = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", `*`, `\*`, `_`, `\_`, `[`, `\[`, `]`, `\]`,
	`|`, `\|`, `~`, `\~`, `#`, `\#`, `!`, `\!`,
)

var htmlReplacer = strings.NewReplacer(`&`, `&amp;`, `<`, `&lt;`, `>`, `&gt;`)

// escapeMarkdown makes s safe as text in a Markdown table cell. Control and
// bidi characters are shown escaped as in the text output, which also keeps
// line breaks out of the row; Markdown syntax is backslash-escaped and HTML
// is entity-encoded, in that order, so the escapes don't break the entities.
func escapeMarkdown(s string) string {
	return htmlReplacer.Replace(markdownReplacer.Replace(Sanitize(s)))
}

// markdownCode returns s as a Markdown code span, also usable in a table
// cell. Inside a code span GitLab renders neither Markdown nor HTML and
// doesn't resolve references such as @user or #123, so text from the scanned
// file can't notify people or link issues from a merge request comment. The
// fence is one backtick longer than any run in s, and the padding spaces are
// stripped again by the renderer.
func markdownCode(s string) string {
	s = strings.ReplaceAll(Sanitize(s), "|", `\|`)
	if s == "" {
		return ""
	}
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	return fence + " " + s + " " + fence
}

// escapeXML escapes s for XML text or an attribute value. Characters XML
// cannot carry are replaced with U+FFFD.
func escapeXML(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s)) // a strings.Builder never fails
	return b.String()
}
