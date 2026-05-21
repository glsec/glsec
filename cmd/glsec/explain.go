package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	glsecdocs "github.com/glsec/glsec/docs"
	"github.com/glsec/glsec/internal/color"
	"github.com/glsec/glsec/rules"
)

func runExplain(ruleID string, noColor bool) {
	id := strings.ToUpper(ruleID)

	found := false
	for _, r := range rules.All() {
		if r.ID() == id {
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "error: unknown rule %q\n", id)
		os.Exit(2)
	}

	raw, err := glsecdocs.FS.ReadFile("rules/" + id + ".md")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: no documentation found for %s\n", id)
		os.Exit(2)
	}

	doc := parseExplainDoc(raw)
	colorEnabled := color.IsEnabled(noColor, os.Stdout)
	renderExplainDoc(id, doc, colorEnabled)
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
	lines := strings.Split(string(content), "\n")
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

func renderExplainDoc(id string, doc explainDoc, colorEnabled bool) {
	fmt.Printf("%s\n", color.Bold(id+" — "+doc.title, colorEnabled))
	fmt.Printf("Severity: %s\n", doc.severity)
	if doc.owasp != "" {
		fmt.Printf("OWASP:    %s\n", doc.owasp)
	}
	if doc.risk != "" {
		fmt.Printf("\nRisk:\n")
		for _, line := range wrapWords(doc.risk, 70) {
			fmt.Printf("  %s\n", line)
		}
	}
	if doc.safeAlt != "" {
		fmt.Printf("\nSafe alternative:\n")
		for _, line := range strings.Split(strings.TrimRight(doc.safeAlt, "\n"), "\n") {
			fmt.Printf("  %s\n", line)
		}
	}
	fmt.Printf("\nDocs: https://glsec.dev/rules/%s\n", id)
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
