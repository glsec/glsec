// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	glsecdocs "github.com/glsec/glsec/docs"
	"github.com/glsec/glsec/internal/color"
	"github.com/glsec/glsec/rules"
)

func runExplain(ruleID string, noColor bool, stdout, stderr io.Writer) int {
	id := strings.ToUpper(ruleID)

	found := false
	for _, r := range rules.All() {
		if r.ID() == id {
			found = true
			break
		}
	}
	if !found {
		_, _ = fmt.Fprintf(stderr, "error: unknown rule %q\n", id)
		return 2
	}

	raw, err := glsecdocs.FS.ReadFile("rules/" + id + ".md")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: no documentation found for %s\n", id)
		return 2
	}

	doc := parseExplainDoc(raw)
	colorEnabled := color.IsEnabled(noColor, stdout)
	renderExplainDoc(stdout, id, doc, colorEnabled)
	return 0
}

var (
	reExplainTitle    = regexp.MustCompile(`^#\s+\S+\s+[—–-]+\s+(.+)$`)
	reExplainSeverity = regexp.MustCompile(`^\*\*Severity:\*\*\s+(.+)$`)
	reExplainOWASP    = regexp.MustCompile(`^\*\*OWASP:\*\*\s+\[([^\]]+)\]`)
)

type explainDoc struct {
	title    string
	severity string
	owasp    string
	risk     string
	safeAlt  string
}

func parseExplainDoc(content []byte) explainDoc {
	// Git on Windows may check the embedded docs out with CRLF line endings.
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	var doc explainDoc
	var section string
	var inCode bool
	var riskDone, safeAltDone bool
	var riskParts []string

	for _, line := range lines {
		if doc.title == "" {
			if m := reExplainTitle.FindStringSubmatch(line); m != nil {
				doc.title = strings.TrimSpace(m[1])
				continue
			}
		}
		if doc.severity == "" {
			if m := reExplainSeverity.FindStringSubmatch(line); m != nil {
				sev := strings.ReplaceAll(m[1], "`", "")
				doc.severity = strings.TrimSpace(sev)
				continue
			}
		}
		if doc.owasp == "" {
			if m := reExplainOWASP.FindStringSubmatch(line); m != nil {
				doc.owasp = m[1]
				continue
			}
		}

		if strings.HasPrefix(line, "## ") {
			if section == "Risk" || section == "What glsec checks" {
				riskDone = true
			}
			section = strings.TrimPrefix(line, "## ")
			inCode = false
			continue
		}

		switch section {
		case "Risk", "What glsec checks":
			if riskDone {
				continue
			}
			if line == "" && len(riskParts) > 0 {
				riskDone = true
			} else if line != "" {
				riskParts = append(riskParts, strings.ReplaceAll(line, "`", ""))
			}
		case "Safe alternative", "Safe alternatives":
			if safeAltDone {
				continue
			}
			if strings.HasPrefix(line, "```") {
				if !inCode {
					inCode = true
				} else {
					inCode = false
					safeAltDone = true
				}
				continue
			}
			if inCode {
				if doc.safeAlt != "" {
					doc.safeAlt += "\n" + line
				} else {
					doc.safeAlt = line
				}
			}
		}
	}

	doc.risk = strings.Join(riskParts, " ")
	return doc
}

func renderExplainDoc(w io.Writer, id string, doc explainDoc, colorEnabled bool) {
	_, _ = fmt.Fprintf(w, "%s\n", color.Bold(id+" — "+doc.title, colorEnabled))
	_, _ = fmt.Fprintf(w, "Severity: %s\n", doc.severity)
	if doc.owasp != "" {
		_, _ = fmt.Fprintf(w, "OWASP:    %s\n", doc.owasp)
	}
	if doc.risk != "" {
		_, _ = fmt.Fprintf(w, "\nRisk:\n")
		for _, line := range wrapWords(doc.risk, 70) {
			_, _ = fmt.Fprintf(w, "  %s\n", line)
		}
	}
	if doc.safeAlt != "" {
		_, _ = fmt.Fprintf(w, "\nSafe alternative:\n")
		for _, line := range strings.Split(strings.TrimRight(doc.safeAlt, "\n"), "\n") {
			_, _ = fmt.Fprintf(w, "  %s\n", line)
		}
	}
	_, _ = fmt.Fprintf(w, "\nDocs: https://glsec.dev/rules/%s\n", id)
}

func wrapWords(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	var cur strings.Builder
	for _, w := range words {
		if cur.Len() > 0 && cur.Len()+1+len(w) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(w)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}
