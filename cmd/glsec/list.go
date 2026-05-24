package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
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

func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text or json")
	owaspFilter := fs.String("owasp", "", "filter by OWASP category (e.g. CICD-SEC-4)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: glsec list [--format text|json] [--owasp CICD-SEC-N]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

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
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(infos); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
	case "text":
		printRuleTable(infos)
	default:
		fmt.Fprintf(os.Stderr, "unknown format %q — use text or json\n", *format)
		os.Exit(2)
	}
}

func printRuleTable(infos []ruleInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEVERITY\tOWASP\tDESCRIPTION")
	for _, info := range infos {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			info.ID, info.Severity, strings.Join(info.OWASP, ", "), info.Description)
	}
	_ = w.Flush()
	fmt.Printf("\n%d rules total\n", len(infos))
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
