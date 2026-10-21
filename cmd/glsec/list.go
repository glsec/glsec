// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	glsecdocs "github.com/glsec/glsec/docs"
	"github.com/glsec/glsec/rules"
)

type ruleInfo struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	OWASP       []string `json:"owasp"`
	Description string   `json:"description"`
}

func runList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	owaspFilter := fs.String("owasp", "", "filter by OWASP category (e.g. CICD-SEC-4)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: glsec list [--format text|json] [--owasp CICD-SEC-N]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	wantOWASP := strings.ToUpper(strings.TrimSpace(*owaspFilter))

	var infos []ruleInfo
	for _, r := range rules.All() {
		id := r.ID()
		cats := rules.OWASPCategories(id)
		if wantOWASP != "" && !containsFold(cats, wantOWASP) {
			continue
		}
		info := ruleInfo{ID: id, OWASP: cats}
		if raw, err := glsecdocs.FS.ReadFile("rules/" + id + ".md"); err == nil {
			doc := parseExplainDoc(raw)
			info.Severity = normalizeSeverity(doc.severity)
			info.Description = strings.ReplaceAll(doc.title, "`", "")
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })

	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(infos); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	case "text":
		printRuleTable(stdout, infos)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown format %q — use text or json\n", *format)
		return 2
	}
	return 0
}

func printRuleTable(out io.Writer, infos []ruleInfo) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tSEVERITY\tOWASP\tDESCRIPTION")
	for _, info := range infos {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			info.ID, info.Severity, strings.Join(info.OWASP, ", "), info.Description)
	}
	_ = w.Flush()
	_, _ = fmt.Fprintf(out, "\n%d rules total\n", len(infos))
}

// normalizeSeverity reduces a doc severity line to a compact table value.
func normalizeSeverity(s string) string {
	low := strings.ToLower(s)
	hasErr := strings.Contains(low, "error")
	hasWarn := strings.Contains(low, "warn")
	switch {
	case hasErr && hasWarn:
		return "error/warn"
	case hasErr:
		return "error"
	case hasWarn:
		return "warn"
	case strings.Contains(low, "info"):
		return "info"
	default:
		return "varies"
	}
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
