package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/rules"
)

func main() {
	formatFlag := flag.String("format", "text", "output format: text, json, sarif")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: glsec [--format text|json|sarif] <file>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}

	format, ok := output.ParseFormat(*formatFlag)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown format %q — use text, json, or sarif\n", *formatFlag)
		os.Exit(2)
	}

	file := flag.Arg(0)
	doc, err := parser.ParseFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	var findings []finding.Finding
	for _, rule := range rules.All() {
		findings = append(findings, rule.Check(doc.Root, file)...)
	}

	if err := output.Write(os.Stdout, format, findings); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}
