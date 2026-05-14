package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/validate"
	"github.com/glsec/glsec/rules"
)

// Set via ldflags at build time by GoReleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	formatFlag := flag.String("format", "text", "output format: text, json, sarif")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: glsec [--format text|json|sarif] <file>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("glsec %s (commit %s, built %s)\n", version, commit, date)
		return
	}

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

	warns, valErr := validate.File(file, doc)
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if valErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", valErr)
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
