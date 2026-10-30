// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/glsec/glsec/internal/finding"
)

// GitLabSASTSchemaVersion is the GitLab security report schema the gitlab-sast
// format follows. 15.2.1 is read by every GitLab release that has the 15.x
// schemas, newer GitLab included.
const GitLabSASTSchemaVersion = "15.2.1"

// GitLab SAST report, uploaded with artifacts:reports:sast. On GitLab Ultimate
// its findings appear in the vulnerability report and the merge request
// security widget (#846). Schema:
// https://gitlab.com/gitlab-org/security-products/security-report-schemas
type gitlabSASTReport struct {
	Version         string              `json:"version"`
	Scan            gitlabSASTScan      `json:"scan"`
	Vulnerabilities []gitlabSASTFinding `json:"vulnerabilities"`
}

type gitlabSASTScan struct {
	Analyzer  gitlabSASTTool      `json:"analyzer"`
	Scanner   gitlabSASTTool      `json:"scanner"`
	Type      string              `json:"type"`
	StartTime string              `json:"start_time"`
	EndTime   string              `json:"end_time"`
	Status    string              `json:"status"`
	Messages  []gitlabSASTMessage `json:"messages,omitempty"`
}

type gitlabSASTMessage struct {
	Level string `json:"level"`
	Value string `json:"value"`
}

type gitlabSASTTool struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	URL     string           `json:"url"`
	Version string           `json:"version"`
	Vendor  gitlabSASTVendor `json:"vendor"`
}

type gitlabSASTVendor struct {
	Name string `json:"name"`
}

type gitlabSASTFinding struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Solution    string                 `json:"solution,omitempty"`
	Identifiers []gitlabSASTIdentifier `json:"identifiers"`
	Location    gitlabSASTLocation     `json:"location"`
}

type gitlabSASTIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type gitlabSASTLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
}

// GitLabSASTMeta supplies what the report needs beyond the findings. Every
// function may be nil.
type GitLabSASTMeta struct {
	Version   string                    // glsec's version
	Rule      func(id string) SARIFRule // title and fix text of a rule
	CWE       func(ruleID string) string
	OWASP     func(ruleID string) []string
	OWASPName func(category string) string
	Start     time.Time // when the scan started; the report's end time is Start too
}

func gitlabSASTSeverity(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "High"
	case finding.Warn:
		return "Medium"
	case finding.Info:
		return "Low"
	default:
		return "Unknown"
	}
}

// gitlabSASTID returns a UUID-shaped ID derived from the finding, so the same
// finding keeps its ID from one pipeline to the next. GitLab matches findings
// across pipelines by location and primary identifier; the ID only has to be
// unique within the report.
func gitlabSASTID(f finding.Finding) string {
	fields, _ := json.Marshal([]any{f.RuleID, f.File, f.Line, f.Job, f.Message}) // strings and ints always marshal
	h := sha256.Sum256(fields)
	h[6] = h[6]&0x0f | 0x50 // version 5 style
	h[8] = h[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// WriteGitLabSAST writes findings as a GitLab SAST report. With scan errors
// the scan's status is "failure" and each error is a fatal message.
func WriteGitLabSAST(w io.Writer, findings []finding.Finding, meta GitLabSASTMeta, opts ...WriteOption) error {
	cwd, _ := os.Getwd()
	version := meta.Version
	if version == "" {
		version = "dev"
	}
	tool := gitlabSASTTool{ID: "glsec", Name: "glsec", URL: SiteURL, Version: version, Vendor: gitlabSASTVendor{Name: "glsec"}}
	at := meta.Start.UTC().Format("2006-01-02T15:04:05")
	report := gitlabSASTReport{
		Version: GitLabSASTSchemaVersion,
		Scan: gitlabSASTScan{
			Analyzer: tool, Scanner: tool, Type: "sast",
			StartTime: at, EndTime: at, Status: "success",
		},
		Vulnerabilities: make([]gitlabSASTFinding, 0, len(findings)),
	}
	for _, e := range reportErrors(writeOptions(opts).errors) {
		report.Scan.Status = "failure"
		report.Scan.Messages = append(report.Scan.Messages, gitlabSASTMessage{Level: "fatal", Value: e.Message})
	}
	for _, f := range findings {
		// Use the reported path for both the location and its stable ID.
		f.File, _ = reportPath(f.File, cwd)
		report.Vulnerabilities = append(report.Vulnerabilities, gitlabSASTVuln(f, meta))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report) // a bytes.Buffer never fails and the report always marshals
	_, err := io.WriteString(w, escapeBidiJSON(buf.String()))
	return err
}

func gitlabSASTVuln(f finding.Finding, meta GitLabSASTMeta) gitlabSASTFinding {
	url := RuleURL(f.RuleID)
	name := f.RuleID
	if meta.Rule != nil {
		if title := meta.Rule(f.RuleID).Title; title != "" {
			name += ": " + title
		}
	}
	// The message, job and path come from the scanned file; GitLab shows
	// them in its UI, so control and bidi characters are escaped as in the
	// terminal output. GitLab decodes the JSON before rendering, so escaping
	// the report bytes alone would still show the raw characters.
	description := Sanitize(f.Message)
	if f.Job != "" {
		description += " (job: " + Sanitize(f.Job) + ")"
	}
	// The first identifier is the primary one: GitLab groups and tracks
	// findings by it.
	ids := []gitlabSASTIdentifier{{Type: "glsec_rule", Name: f.RuleID, Value: f.RuleID, URL: url}}
	if meta.CWE != nil {
		if cwe := meta.CWE(f.RuleID); cwe != "" {
			n := strings.TrimPrefix(cwe, "CWE-")
			ids = append(ids, gitlabSASTIdentifier{Type: "cwe", Name: cwe, Value: n, URL: "https://cwe.mitre.org/data/definitions/" + n + ".html"})
		}
	}
	if meta.OWASP != nil {
		for _, cat := range meta.OWASP(f.RuleID) {
			label := cat
			if meta.OWASPName != nil {
				if n := meta.OWASPName(cat); n != "" {
					label = cat + " " + n
				}
			}
			ids = append(ids, gitlabSASTIdentifier{Type: "owasp_cicd", Name: label, Value: cat})
		}
	}
	var solution string
	if url != "" {
		solution = "See " + url
	}
	line := f.Line
	if line < 1 {
		line = 1
	}
	return gitlabSASTFinding{
		ID:          gitlabSASTID(f),
		Name:        name,
		Description: description,
		Severity:    gitlabSASTSeverity(f.Severity),
		Solution:    solution,
		Identifiers: ids,
		Location:    gitlabSASTLocation{File: Sanitize(f.File), StartLine: line},
	}
}
