// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/glsec/glsec/internal/inventory"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
)

// runInventory writes a CycloneDX BOM of the images and includes a pipeline
// pulls in (#830). It reports no findings, so it exits 0 unless the file can't
// be read or parsed.
func runInventory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "cyclonedx", "output format: cyclonedx")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: glsec inventory [--format cyclonedx] [file]")
		_, _ = fmt.Fprintln(stderr, "       Lists the images, services and includes of a pipeline as a CycloneDX 1.6 BOM.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *format != "cyclonedx" {
		_, _ = fmt.Fprintf(stderr, "unknown inventory format %q — use cyclonedx\n", output.Sanitize(*format))
		return 2
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return 2
	}
	file := ".gitlab-ci.yml"
	if fs.NArg() == 1 {
		file = fs.Arg(0)
	}
	doc, err := parser.ParseFile(file)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", output.Sanitize(err.Error()))
		return 2
	}
	if err := inventory.WriteCycloneDX(stdout, filepath.ToSlash(file), version, inventory.Collect(doc)); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", output.Sanitize(err.Error()))
		return 2
	}
	return 0
}
