// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"text/template"
	"time"

	"github.com/glsec/glsec/internal/color"
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/redact"
	"github.com/glsec/glsec/internal/suppress"
)

type Format string

const (
	FormatText        Format = "text"
	FormatJSON        Format = "json"
	FormatSARIF       Format = "sarif"
	FormatCodeClimate Format = "codeclimate"
	FormatTable       Format = "table"
	FormatJUnit       Format = "junit"
	FormatGitLabSAST  Format = "gitlab-sast"
	FormatTemplate    Format = "template"
)

func ParseFormat(s string) (Format, bool) {
	switch Format(s) {
	case FormatText, FormatJSON, FormatSARIF, FormatCodeClimate, FormatTable, FormatJUnit, FormatGitLabSAST, FormatTemplate:
		return Format(s), true
	default:
		return "", false
	}
}

// WriteOption changes how Write renders.
type WriteOption func(*writeConfig)

type writeConfig struct {
	noRedact     bool
	errors       []ScanError
	suppressed   []finding.Suppressed
	template     *template.Template
	templateMeta TemplateMeta
	sources      map[string][]byte
}

// WithSources gives the text output the content each file was parsed from,
// by path, for its source lines. Without it they are read from disk, which
// for stdin input doesn't hold what was scanned (#833).
func WithSources(sources map[string][]byte) WriteOption {
	return func(c *writeConfig) { c.sources = sources }
}

// NoRedact shows the source lines of the text output as they are, secrets
// included (--no-redact, #831). Messages are masked by the caller.
func NoRedact() WriteOption { return func(c *writeConfig) { c.noRedact = true } }

// Write renders findings in the given format. isTTY reports whether w is an
// interactive terminal; the text format uses it to decide whether to print the
// clean-run summary line (suppressed when piped, e.g. in CI).
func Write(w io.Writer, format Format, findings []finding.Finding, jobCount int, colorEnabled, isTTY bool, opts ...WriteOption) error {
	cfg := writeOptions(opts)
	switch format {
	case FormatJSON:
		return writeJSON(w, findings, cfg.suppressed, cfg.errors, nil, nil)
	case FormatSARIF:
		return writeSARIF(w, findings, cfg.suppressed, cfg.errors, SARIFTool{}, nil, nil, nil, nil, nil, nil)
	case FormatCodeClimate:
		return writeCodeClimate(w, findings, cfg.errors)
	case FormatJUnit:
		return writeJUnit(w, findings, cfg.errors)
	case FormatGitLabSAST:
		return WriteGitLabSAST(w, findings, GitLabSASTMeta{Start: time.Now()}, opts...)
	case FormatTemplate:
		if cfg.template == nil {
			return errors.New("--format template needs a template (--template)")
		}
		return writeTemplate(w, cfg.template, findings, cfg.errors, jobCount, cfg.templateMeta)
	case FormatTable:
		if err := writeTable(w, findings, jobCount, colorEnabled, isTTY); err != nil {
			return err
		}
		return writeSuppressedSummary(w, cfg.suppressed, len(findings) > 0)
	default:
		if err := writeText(w, findings, jobCount, colorEnabled, isTTY, !cfg.noRedact, cfg.sources); err != nil {
			return err
		}
		return writeSuppressedSummary(w, cfg.suppressed, len(findings) > 0)
	}
}

// writeTable renders findings as an aligned column table, similar to
// osv-scanner's table output. Columns are tab-separated and padded with
// text/tabwriter. On a clean run it falls back to the same summary line as the
// text format, which is only emitted on an interactive terminal (issue #273).
//
// The severity is coloured after tabwriter has aligned the lines: tabwriter
// counts the bytes of ANSI escapes as width, which would shift the columns
// (#726). Sanitize keeps line breaks out of the cells, so output line i+1 is
// finding i and starts with its severity.
func writeTable(w io.Writer, findings []finding.Finding, jobCount int, colorOn, isTTY bool) error {
	if len(findings) == 0 {
		if isTTY {
			_, err := fmt.Fprintf(w, "Scanned %d jobs, 0 issues found.\n", jobCount)
			return err
		}
		return nil
	}

	// The table is rendered into buf, and writes to a bytes.Buffer don't fail;
	// only the writes to w below can.
	var buf bytes.Buffer
	tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SEVERITY\tRULE\tJOB\tFILE\tLINE\tMESSAGE")
	for _, f := range findings {
		job := Sanitize(f.Job)
		if job == "" {
			job = "-"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n",
			strings.ToUpper(string(f.Severity)), f.RuleID, job, Sanitize(f.File), f.Line, Sanitize(f.Message))
	}
	_ = tw.Flush()
	if !colorOn {
		_, err := buf.WriteTo(w)
		return err
	}

	lines := strings.SplitAfter(buf.String(), "\n")
	for i, line := range lines {
		if i >= 1 && i <= len(findings) {
			line = colorTableSeverity(line, findings[i-1].Severity)
		}
		if _, err := io.WriteString(w, line); err != nil {
			return err
		}
	}
	return nil
}

// colorTableSeverity colours the severity label a table row starts with.
func colorTableSeverity(line string, sev finding.Severity) string {
	label := strings.ToUpper(string(sev))
	rest := strings.TrimPrefix(line, label)
	switch sev {
	case finding.Error:
		return color.Red(label, true) + rest
	case finding.Warn:
		return color.Yellow(label, true) + rest
	}
	return line
}

// writeText renders findings as compiler-style diagnostics: a header carrying
// severity, rule and message, the location, then the offending source line with
// a caret at the recorded column. When the source cannot be read the header is
// still printed, so output never depends on the file still being there.
func writeText(w io.Writer, findings []finding.Finding, jobCount int, col, isTTY, redactSource bool, sources map[string][]byte) error {
	src := newSourceCache(redactSource, sources)
	for i, f := range findings {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if err := writeDiagnostic(w, f, src, col); err != nil {
			return err
		}
	}
	// The clean-run summary is a human-facing nicety: only emit it on an
	// interactive terminal. When piped (e.g. a CI runner), keep stdout empty so
	// the line cannot be duplicated by the executor's trace handling (issue #273).
	if len(findings) == 0 && isTTY {
		_, err := fmt.Fprintf(w, "Scanned %d jobs, 0 issues found.\n", jobCount)
		return err
	}
	return nil
}

// writeSuppressedSummary tells the text and table reader that findings were
// suppressed, so a suppression doesn't look like a fix (#834). It follows the
// findings after a blank line.
func writeSuppressedSummary(w io.Writer, suppressed []finding.Suppressed, afterFindings bool) error {
	if len(suppressed) == 0 {
		return nil
	}
	inline := 0
	for _, s := range suppressed {
		if s.Source == finding.SourceInline {
			inline++
		}
	}
	var sources []string
	if inline > 0 {
		sources = append(sources, fmt.Sprintf("%d inline", inline))
	}
	if n := len(suppressed) - inline; n > 0 {
		sources = append(sources, fmt.Sprintf("%d %s", n, suppress.IgnoreFile))
	}
	noun := "findings"
	if len(suppressed) == 1 {
		noun = "finding"
	}
	sep := ""
	if afterFindings {
		sep = "\n"
	}
	_, err := fmt.Fprintf(w, "%s%d %s suppressed (%s); run with --no-ignores to show them\n", sep, len(suppressed), noun, strings.Join(sources, ", "))
	return err
}

// writeDiagnostic renders one finding. The source block is best-effort: a
// missing file, an out-of-range line or a zero column each degrade to printing
// less, never to an error.
func writeDiagnostic(w io.Writer, f finding.Finding, src *sourceCache, colorOn bool) error {
	sev := string(f.Severity)
	switch f.Severity {
	case finding.Error:
		sev = color.Red(sev, colorOn)
	case finding.Warn:
		sev = color.Yellow(sev, colorOn)
	}
	if _, err := fmt.Fprintf(w, "%s[%s]: %s\n", sev, color.Bold(f.RuleID, colorOn), Sanitize(f.Message)); err != nil {
		return err
	}

	loc := fmt.Sprintf("%s:%d", Sanitize(f.File), f.Line)
	if f.Col > 0 {
		loc += ":" + strconv.Itoa(f.Col)
	}
	if f.Job != "" {
		loc += " (job: " + Sanitize(f.Job) + ")"
	}
	if _, err := fmt.Fprintf(w, "  --> %s\n", color.Bold(loc, colorOn)); err != nil {
		return err
	}

	line, ok := src.line(f.File, f.Line)
	if !ok {
		return nil
	}
	num := strconv.Itoa(f.Line)
	pad := strings.Repeat(" ", len(num))
	if _, err := fmt.Fprintf(w, "%s |\n%s | %s\n", pad, num, sanitizeSource(line)); err != nil {
		return err
	}
	if f.Col > 0 {
		if _, err := fmt.Fprintf(w, "%s | %s^\n", pad, strings.Repeat(" ", f.Col-1)); err != nil {
			return err
		}
	}
	return nil
}

// sourceCache takes a file's lines from the parsed sources, or reads the file
// lazily, so several findings in one file cost a single read. A file that
// cannot be read is remembered as absent rather than retried.
// With redact set, secret values in the lines are masked (#831).
type sourceCache struct {
	files   map[string][]string
	sources map[string][]byte
	redact  bool
}

func newSourceCache(redact bool, sources map[string][]byte) *sourceCache {
	return &sourceCache{files: make(map[string][]string), sources: sources, redact: redact}
}

func (c *sourceCache) line(path string, n int) (string, bool) {
	lines, cached := c.files[path]
	if !cached {
		data, ok := c.sources[path]
		var err error
		if !ok {
			data, err = parser.ReadFile(path)
		}
		if err == nil {
			lines = strings.Split(string(data), "\n")
			if c.redact {
				for i := range lines {
					lines[i] = redact.String(lines[i])
				}
			}
		}
		c.files[path] = lines
	}
	if n < 1 || n > len(lines) {
		return "", false
	}
	return strings.TrimRight(lines[n-1], "\r"), true
}

type jsonFinding struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Job      string   `json:"job,omitempty"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Message  string   `json:"message"`
	OWASP    []string `json:"owasp,omitempty"`
	ASVS     []string `json:"asvs,omitempty"`
}

type jsonOutput struct {
	Findings []jsonFinding `json:"findings"`
	// Suppressed is a separate array, so a consumer that reads findings, and
	// a JSON snapshot used as --baseline, see what they saw before (#834).
	Suppressed []jsonSuppressed `json:"suppressed,omitempty"`
	Errors     []jsonError      `json:"errors,omitempty"`
}

type jsonSuppressed struct {
	jsonFinding
	Suppression jsonSuppression `json:"suppression"`
}

type jsonSuppression struct {
	Source  string `json:"source"`
	Reason  string `json:"reason,omitempty"`
	Expires string `json:"expires,omitempty"`
}

type jsonError struct {
	File    string `json:"file,omitempty"`
	Message string `json:"message"`
}

// WriteJSON writes findings as JSON. owasp and asvs, if non-nil, are called
// per finding to populate the "owasp" and "asvs" fields. Scan errors go in
// an "errors" array.
func WriteJSON(w io.Writer, findings []finding.Finding, owasp, asvs func(string) []string, opts ...WriteOption) error {
	cfg := writeOptions(opts)
	return writeJSON(w, findings, cfg.suppressed, cfg.errors, owasp, asvs)
}

func writeJSON(w io.Writer, findings []finding.Finding, suppressed []finding.Suppressed, errs []ScanError, owasp, asvs func(string) []string) error {
	out := jsonOutput{Findings: jsonFindings(findings, owasp, asvs), Errors: jsonErrors(errs)}
	if len(suppressed) > 0 {
		fs := make([]finding.Finding, len(suppressed))
		for i, s := range suppressed {
			fs[i] = s.Finding
		}
		for i, jf := range jsonFindings(fs, owasp, asvs) {
			s := suppressed[i]
			out.Suppressed = append(out.Suppressed, jsonSuppressed{jf, jsonSuppression{Source: s.Source, Reason: s.Reason, Expires: s.Expires}})
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out) // a bytes.Buffer never fails and jsonOutput always marshals
	_, err := io.WriteString(w, escapeBidiJSON(buf.String()))
	return err
}

// jsonFindings converts findings to the JSON report's fields, which the
// template format exposes too.
func jsonFindings(findings []finding.Finding, owasp, asvs func(string) []string) []jsonFinding {
	cwd, _ := os.Getwd() // retain supplied absolute paths if cwd is unavailable
	out := make([]jsonFinding, 0, len(findings))
	for _, f := range findings {
		file, _ := reportPath(f.File, cwd)
		jf := jsonFinding{
			Rule:     f.RuleID,
			Severity: string(f.Severity),
			Job:      f.Job,
			File:     file,
			Line:     f.Line,
			Message:  f.Message,
		}
		if owasp != nil {
			jf.OWASP = owasp(f.RuleID)
		}
		if asvs != nil {
			jf.ASVS = asvs(f.RuleID)
		}
		out = append(out, jf)
	}
	return out
}

func jsonErrors(errs []ScanError) []jsonError {
	var out []jsonError
	for _, e := range reportErrors(errs) {
		out = append(out, jsonError(e))
	}
	return out
}

// escapeBidiJSON replaces each bidirectional control character in s with
// its JSON escape, so the encoded output never carries one raw. The
// characters can only occur inside JSON strings here, and escaping them
// keeps the decoded value identical to the original.
var bidiJSONReplacer = strings.NewReplacer(
	"\u202a", `\u202a`,
	"\u202b", `\u202b`,
	"\u202c", `\u202c`,
	"\u202d", `\u202d`,
	"\u202e", `\u202e`,
	"\u2066", `\u2066`,
	"\u2067", `\u2067`,
	"\u2068", `\u2068`,
	"\u2069", `\u2069`,
	"\u200e", `\u200e`,
	"\u200f", `\u200f`,
	"\u061c", `\u061c`,
)

func escapeBidiJSON(s string) string {
	return bidiJSONReplacer.Replace(s)
}

// SARIF 2.1.0 types — minimal subset for GitHub Code Scanning. GitLab reads
// security reports only in its own schema, not SARIF.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool       `json:"tool"`
	Taxonomies []sarifTaxonomy `json:"taxonomies,omitempty"`
	Results    []sarifResult   `json:"results"`
	// Only written when the scan failed, so a clean report stays as it was.
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri"`
	Rules           []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	ShortDescription     *sarifText          `json:"shortDescription,omitempty"`
	FullDescription      *sarifText          `json:"fullDescription,omitempty"`
	Help                 *sarifHelp          `json:"help,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifConfig        `json:"defaultConfiguration,omitempty"`
	Properties           *sarifRuleProps     `json:"properties,omitempty"`
	Relationships        []sarifRelationship `json:"relationships,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

// sarifRuleProps are the rule properties GitHub code scanning reads: tags
// for filtering (external/cwe/cwe-N) and security-severity, which it shows as
// Critical, High, Medium or Low.
type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

// SARIFRule describes a rule for the SARIF rule object; the fields come from
// the rule's documentation. Empty fields are left out.
type SARIFRule struct {
	Title    string           // shortDescription: the alert title
	Risk     string           // fullDescription, and help.text
	Details  string           // help.markdown: the rule doc's section on what it checks
	Fix      string           // a safe alternative, shown as a YAML block in help
	Severity finding.Severity // defaultConfiguration.level and security-severity
}

// SARIFTool is what WriteSARIF says about glsec itself and its rules.
type SARIFTool struct {
	Version string                    // glsec's version; "dev" and "" are left out
	Rule    func(id string) SARIFRule // nil: rules carry only id, helpUri and relationships
}

// securitySeverity maps a severity to GitHub's security-severity score:
// 7.0–8.9 shows as High, 4.0–6.9 as Medium, 0.1–3.9 as Low.
func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "8.0"
	case finding.Warn:
		return "5.0"
	case finding.Info:
		return "2.0"
	}
	return ""
}

type sarifRelationship struct {
	Target sarifRelationshipTarget `json:"target"`
	Kinds  []string                `json:"kinds"`
}

type sarifRelationshipTarget struct {
	ID            string                `json:"id"`
	ToolComponent sarifToolComponentRef `json:"toolComponent"`
}

type sarifToolComponentRef struct {
	Name string `json:"name"`
}

type sarifTaxonomy struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Organization string       `json:"organization"`
	Taxa         []sarifTaxon `json:"taxa"`
}

type sarifTaxon struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifSuppression struct {
	Kind          string                 `json:"kind"`
	Justification string                 `json:"justification,omitempty"`
	Properties    *sarifSuppressionProps `json:"properties,omitempty"`
}

type sarifSuppressionProps struct {
	Expires string `json:"expires"`
}

func sarifResultOf(f finding.Finding, cwd string) sarifResult {
	file, local := reportPath(f.File, cwd)
	location := sarifArtifactLocation{URI: sarifURI(file)}
	if local {
		location.URIBaseID = "%SRCROOT%"
	}
	physical := sarifPhysicalLocation{ArtifactLocation: location}
	// SARIF lines start at 1; a finding on the whole file has none.
	if f.Line > 0 {
		physical.Region = &sarifRegion{StartLine: f.Line}
	}
	return sarifResult{
		RuleID:    f.RuleID,
		Level:     severityToSARIFLevel(f.Severity),
		Message:   sarifMessage{Text: f.Message},
		Locations: []sarifLocation{{PhysicalLocation: physical}},
	}
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
}

type sarifNotification struct {
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

// sarifInvocations reports the scan errors as a failed invocation, the field
// SARIF has for a tool run that didn't complete.
func sarifInvocations(errs []ScanError) []sarifInvocation {
	if len(errs) == 0 {
		return nil
	}
	cwd, _ := os.Getwd()
	inv := sarifInvocation{}
	for _, e := range errs {
		e, local := reportError(e, cwd)
		n := sarifNotification{Level: "error", Message: sarifMessage{Text: e.Message}}
		if e.File != "" {
			loc := sarifArtifactLocation{URI: sarifURI(e.File)}
			if local {
				loc.URIBaseID = "%SRCROOT%"
			}
			n.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: loc}}}
		}
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, n)
	}
	return []sarifInvocation{inv}
}

// sortTaxa orders taxa by ID: they come from a map, and the same findings
// must give the same report.
func sortTaxa(taxa []sarifTaxon) {
	sort.Slice(taxa, func(i, j int) bool { return taxa[i].ID < taxa[j].ID })
}

// sarifURI writes a report path as the URI reference SARIF requires: a space
// or another character a URI can't hold is percent-encoded, / stays. An
// absolute path, one outside the working directory, becomes a file:// URI.
func sarifURI(path string) string {
	if filepath.IsAbs(path) {
		slash := filepath.ToSlash(path)
		if !strings.HasPrefix(slash, "/") {
			slash = "/" + slash // C:/x
		}
		return (&url.URL{Scheme: "file", Path: slash}).String()
	}
	return (&url.URL{Path: path}).EscapedPath()
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func severityToSARIFLevel(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "error"
	case finding.Warn:
		return "warning"
	default:
		return "note"
	}
}

// SiteURL is glsec's website; every rule has a page at RuleURL (#718).
const SiteURL = "https://glsec.github.io"

var (
	glsecRuleRe      = regexp.MustCompile(`^GL[0-9]{3}$`)
	shellcheckRuleRe = regexp.MustCompile(`^SC[0-9]{4}$`)
)

// RuleURL returns the documentation page of a rule: glsec's own rules on the
// website, ShellCheck's on its wiki, and "" for anything else.
func RuleURL(id string) string {
	switch {
	case glsecRuleRe.MatchString(id):
		return SiteURL + "/rules/" + id + "/"
	case shellcheckRuleRe.MatchString(id):
		return "https://www.shellcheck.net/wiki/" + id
	}
	return ""
}

// WriteSARIF writes SARIF output enriched with CWE and OWASP metadata.
// cweID maps a rule ID to its CWE identifier (e.g. "CWE-798").
// cweName maps a CWE identifier to its human-readable name.
// owasp maps a rule ID to its OWASP CI/CD Security Risks categories.
// owaspName maps an OWASP category ID to its human-readable name.
// Pass nil for any parameter to omit that taxonomy.
func WriteSARIF(w io.Writer, findings []finding.Finding, tool SARIFTool,
	cweID func(string) string, cweName func(string) string,
	owasp func(string) []string, owaspName func(string) string,
	asvs func(string) []string, asvsName func(string) string,
	opts ...WriteOption,
) error {
	cfg := writeOptions(opts)
	return writeSARIF(w, findings, cfg.suppressed, cfg.errors, tool, cweID, cweName, owasp, owaspName, asvs, asvsName)
}

func writeSARIF(w io.Writer, findings []finding.Finding, suppressed []finding.Suppressed, errs []ScanError, tool SARIFTool,
	cweID func(string) string, cweName func(string) string,
	owasp func(string) []string, owaspName func(string) string,
	asvs func(string) []string, asvsName func(string) string,
) error {
	cwd, _ := os.Getwd()
	results := make([]sarifResult, 0, len(findings)+len(suppressed))
	for _, f := range findings {
		results = append(results, sarifResultOf(f, cwd))
	}
	// A suppressed finding is a result with suppressions, the SARIF way to
	// say that it was reviewed and accepted rather than fixed (#834).
	all := append([]finding.Finding(nil), findings...)
	for _, s := range suppressed {
		r := sarifResultOf(s.Finding, cwd)
		sup := sarifSuppression{Kind: "inSource", Justification: s.Reason}
		if s.Source == finding.SourceIgnoreFile {
			sup.Kind = "external"
		}
		if s.Expires != "" {
			sup.Properties = &sarifSuppressionProps{Expires: s.Expires}
		}
		r.Suppressions = []sarifSuppression{sup}
		results = append(results, r)
		all = append(all, s.Finding)
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "glsec",
			InformationURI: SiteURL,
		}},
		Results:     results,
		Invocations: sarifInvocations(errs),
	}
	if tool.Version != "" && tool.Version != "dev" {
		run.Tool.Driver.Version = tool.Version
		run.Tool.Driver.SemanticVersion = strings.TrimPrefix(tool.Version, "v")
	}

	seenRules := map[string]bool{}
	seenCWEs := map[string]bool{}
	seenOWASP := map[string]bool{}
	seenASVS := map[string]bool{}

	for _, f := range all {
		if seenRules[f.RuleID] {
			continue
		}
		seenRules[f.RuleID] = true

		var rels []sarifRelationship
		props := &sarifRuleProps{Tags: []string{"security"}}

		if cweID != nil {
			if cwe := cweID(f.RuleID); cwe != "" {
				props.Tags = append(props.Tags, "external/cwe/"+strings.ToLower(cwe))
				rels = append(rels, sarifRelationship{
					Target: sarifRelationshipTarget{ID: cwe, ToolComponent: sarifToolComponentRef{Name: "CWE"}},
					Kinds:  []string{"superset"},
				})
				seenCWEs[cwe] = true
			}
		}

		if owasp != nil {
			for _, cat := range owasp(f.RuleID) {
				rels = append(rels, sarifRelationship{
					Target: sarifRelationshipTarget{ID: cat, ToolComponent: sarifToolComponentRef{Name: "OWASP Top 10 CI/CD Security Risks"}},
					Kinds:  []string{"superset"},
				})
				seenOWASP[cat] = true
			}
		}

		if asvs != nil {
			for _, req := range asvs(f.RuleID) {
				rels = append(rels, sarifRelationship{
					Target: sarifRelationshipTarget{ID: req, ToolComponent: sarifToolComponentRef{Name: "OWASP ASVS"}},
					Kinds:  []string{"superset"},
				})
				seenASVS[req] = true
			}
		}

		rule := sarifRule{ID: f.RuleID, HelpURI: RuleURL(f.RuleID), Relationships: rels}
		if tool.Rule != nil {
			describeSARIFRule(&rule, tool.Rule(f.RuleID), props)
		}
		if rule.HelpURI != "" || len(rels) > 0 || rule.ShortDescription != nil {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}
	}

	if len(seenCWEs) > 0 && cweName != nil {
		taxa := make([]sarifTaxon, 0, len(seenCWEs))
		for cwe := range seenCWEs {
			taxa = append(taxa, sarifTaxon{ID: cwe, Name: cweName(cwe)})
		}
		sortTaxa(taxa)
		run.Taxonomies = append(run.Taxonomies, sarifTaxonomy{
			Name: "CWE", Version: "4.14", Organization: "MITRE", Taxa: taxa,
		})
	}

	if len(seenOWASP) > 0 && owaspName != nil {
		taxa := make([]sarifTaxon, 0, len(seenOWASP))
		for cat := range seenOWASP {
			taxa = append(taxa, sarifTaxon{ID: cat, Name: owaspName(cat)})
		}
		sortTaxa(taxa)
		run.Taxonomies = append(run.Taxonomies, sarifTaxonomy{
			Name: "OWASP Top 10 CI/CD Security Risks", Version: "2022", Organization: "OWASP", Taxa: taxa,
		})
	}

	if len(seenASVS) > 0 && asvsName != nil {
		taxa := make([]sarifTaxon, 0, len(seenASVS))
		for req := range seenASVS {
			taxa = append(taxa, sarifTaxon{ID: req, Name: asvsName(req)})
		}
		sortTaxa(taxa)
		run.Taxonomies = append(run.Taxonomies, sarifTaxonomy{
			Name: "OWASP ASVS", Version: "4.0.3", Organization: "OWASP", Taxa: taxa,
		})
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	_ = enc.Encode(log) // a bytes.Buffer never fails and sarifLog always marshals
	_, err := io.WriteString(w, escapeBidiJSON(buf.String()))
	return err
}

// describeSARIFRule fills in what code scanning shows for a rule: the title,
// the description, a help text with the safe alternative and a link to the
// rule page, the default level, the CWE tags and the security severity.
func describeSARIFRule(rule *sarifRule, info SARIFRule, props *sarifRuleProps) {
	if info.Title != "" {
		rule.ShortDescription = &sarifText{Text: info.Title}
	}
	if info.Risk != "" {
		rule.FullDescription = &sarifText{Text: info.Risk}
	}
	if info.Risk != "" || info.Fix != "" {
		text, md := info.Risk, info.Details
		if md == "" {
			md = info.Risk
		}
		if info.Fix != "" {
			text += "\n\nSafe alternative:\n" + info.Fix
			md += "\n\n**Safe alternative:**\n\n```yaml\n" + info.Fix + "\n```"
		}
		if rule.HelpURI != "" {
			text += "\n\n" + rule.HelpURI
			md += fmt.Sprintf("\n\n[%s on glsec.github.io](%s)", rule.ID, rule.HelpURI)
		}
		rule.Help = &sarifHelp{Text: strings.TrimSpace(text), Markdown: strings.TrimSpace(md)}
	}
	if info.Severity != "" {
		rule.DefaultConfiguration = &sarifConfig{Level: severityToSARIFLevel(info.Severity)}
		props.SecuritySeverity = securitySeverity(info.Severity)
	}
	rule.Properties = props
}

// Code Climate JSON — consumed natively by GitLab's Code Quality widget
// (artifacts:reports:codequality). Spec:
// https://github.com/codeclimate/platform/blob/master/spec/analyzers/SPEC.md
type codeClimateIssue struct {
	Type        string              `json:"type"`
	CheckName   string              `json:"check_name"`
	Description string              `json:"description"`
	Categories  []string            `json:"categories"`
	Severity    string              `json:"severity"`
	Fingerprint string              `json:"fingerprint"`
	Location    codeClimateLocation `json:"location"`
}

type codeClimateLocation struct {
	Path  string           `json:"path"`
	Lines codeClimateLines `json:"lines"`
}

type codeClimateLines struct {
	Begin int `json:"begin"`
}

func severityToCodeClimate(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "critical"
	case finding.Warn:
		return "major"
	default:
		return "info"
	}
}

// codeClimateFingerprint returns a stable one-way ID for GitLab Code Quality's
// required fingerprint field. The SHA256 is a content hash over finding
// metadata, not password hashing — no secret is stored or verified against it.
// The fields are hashed as a JSON array: joined with a separator, a job name or
// message containing it could make two findings hash alike (#647).
func codeClimateFingerprint(f finding.Finding) string {
	fields, _ := json.Marshal([]any{f.RuleID, f.File, f.Job, f.Message, f.Line}) // strings and an int always marshal
	h := sha256.Sum256(fields)
	return hex.EncodeToString(h[:])
}

// writeCodeClimate writes findings in the Code Climate JSON format
// consumed by GitLab's Code Quality (artifacts:reports:codequality). A scan
// error becomes a blocker issue, so the merge request widget shows it.
func writeCodeClimate(w io.Writer, findings []finding.Finding, errs []ScanError) error {
	cwd, _ := os.Getwd()
	out := make([]codeClimateIssue, 0, len(findings))
	for _, f := range findings {
		// Hash the reported path too, so absolute and relative invocations
		// identify the same issue in the Code Quality widget.
		f.File, _ = reportPath(f.File, cwd)
		out = append(out, codeClimateIssue{
			Type:        "issue",
			CheckName:   f.RuleID,
			Description: f.Message,
			Categories:  []string{"Security"},
			Severity:    severityToCodeClimate(f.Severity),
			Fingerprint: codeClimateFingerprint(f),
			Location: codeClimateLocation{
				Path:  f.File,
				Lines: codeClimateLines{Begin: f.Line},
			},
		})
	}
	for _, e := range reportErrors(errs) {
		out = append(out, codeClimateError(e))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out) // a bytes.Buffer never fails and codeClimateIssue always marshals
	_, err := io.WriteString(w, escapeBidiJSON(buf.String()))
	return err
}

type junitTestsuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Suites   []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name     string `xml:"name,attr"`
	Tests    int    `xml:"tests,attr"`
	Failures int    `xml:"failures,attr"`
	// The JUnit schema requires errors on a testsuite, also when it is 0.
	Errors int             `xml:"errors,attr"`
	Cases  []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitFailure `xml:"error,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// writeJUnit renders findings as a JUnit XML report, consumed by GitLab's
// pipeline Tests tab and MR test widget via artifacts:reports:junit (all tiers).
// Each finding becomes one failing test case; a clean run emits a single
// passing case so the widget is not empty. A scan error becomes a test case
// with an <error> element.
func writeJUnit(w io.Writer, findings []finding.Finding, errs []ScanError) error {
	cwd, _ := os.Getwd()
	suite := junitTestsuite{Name: "glsec"}
	errs = reportErrors(errs)
	if len(findings) == 0 && len(errs) == 0 {
		suite.Tests = 1
		suite.Cases = []junitTestcase{{Name: "glsec: no findings", Classname: "glsec"}}
	} else {
		for _, f := range findings {
			f.File, _ = reportPath(f.File, cwd)
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			name := f.RuleID
			if f.Job != "" {
				name = fmt.Sprintf("%s in job %q", f.RuleID, f.Job)
			}
			suite.Cases = append(suite.Cases, junitTestcase{
				Name:      name,
				Classname: loc,
				Failure: &junitFailure{
					Message: f.Message,
					Type:    string(f.Severity),
					Text:    fmt.Sprintf("%s [%s] %s", f.RuleID, f.Severity, loc),
				},
			})
		}
		for _, e := range errs {
			classname := e.File
			if classname == "" {
				classname = "glsec"
			}
			suite.Cases = append(suite.Cases, junitTestcase{
				Name:      "glsec: scan failed",
				Classname: classname,
				Error:     &junitFailure{Message: e.Message, Type: "scan-error", Text: e.Message},
			})
		}
		suite.Tests = len(findings) + len(errs)
		suite.Failures = len(findings)
		suite.Errors = len(errs)
	}
	root := junitTestsuites{
		Name:     "glsec",
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Errors:   suite.Errors,
		Suites:   []junitTestsuite{suite},
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
