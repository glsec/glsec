// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/glsec/glsec/internal/inventory"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
)

// runInventory writes a CycloneDX BOM of the images and includes a pipeline
// pulls in (#830), or with --format jobs the jobs glsec scans (#930). It
// reports no findings, so it exits 0 unless the file can't be read or parsed.
func runInventory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "cyclonedx", "output format: cyclonedx, jobs")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: glsec inventory [--format cyclonedx|jobs] [file]")
		_, _ = fmt.Fprintln(stderr, "       Lists the images, services and includes of a pipeline as a CycloneDX 1.6 BOM,")
		_, _ = fmt.Fprintln(stderr, "       or with --format jobs the jobs glsec scans, as JSON.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *format != "cyclonedx" && *format != "jobs" {
		_, _ = fmt.Fprintf(stderr, "unknown inventory format %q — use cyclonedx or jobs\n", output.Sanitize(*format))
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
	if *format == "jobs" {
		return writeJobs(stdout, stderr, doc)
	}
	if err := inventory.WriteCycloneDX(stdout, filepath.ToSlash(file), version, inventory.Collect(doc)); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", output.Sanitize(err.Error()))
		return 2
	}
	return 0
}

// writeJobs lists the visible jobs of the document glsec scans, the ones
// GitLab would create: hidden jobs (".name") are templates and left out.
func writeJobs(stdout, stderr io.Writer, doc *parser.Document) int {
	type job struct {
		Name string `json:"name"`
		Line int    `json:"line"`
	}
	out := struct {
		Jobs []job `json:"jobs"`
	}{Jobs: []job{}}
	parser.EachJob(doc.Root, func(name, _ *yaml.Node) {
		if !strings.HasPrefix(name.Value, ".") {
			out.Jobs = append(out.Jobs, job{name.Value, name.Line})
		}
	})
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", output.Sanitize(err.Error()))
		return 2
	}
	return 0
}
