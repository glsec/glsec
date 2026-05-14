package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/rules"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: glsec <file>")
		os.Exit(2)
	}

	file := os.Args[1]
	doc, err := parser.ParseFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	var findings []finding.Finding
	for _, rule := range rules.All() {
		findings = append(findings, rule.Check(doc.Root, file)...)
	}

	for _, f := range findings {
		fmt.Printf("%-6s %s:%d  %s  %s\n",
			strings.ToUpper(string(f.Severity)),
			f.File, f.Line,
			f.RuleID,
			f.Message,
		)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}
