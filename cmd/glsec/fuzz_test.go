// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
	gitlabver "github.com/glsec/glsec/internal/version"
)

// FuzzScan takes the path a scan takes: parse, collect findings with inline
// suppressions, then render every output format.
func FuzzScan(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "fixtures", "*.yml"))
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // G304: test reads the repository's own fixtures
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	formats := []output.Format{
		output.FormatText, output.FormatTable, output.FormatJSON,
		output.FormatSARIF, output.FormatCodeClimate, output.FormatJUnit,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := parser.Parse(data, "fuzz.yml")
		if err != nil {
			return
		}
		findings, _, _, _ := collectFindings(doc, "fuzz.yml", config.Default(), gitlabver.Version{}, false, true)
		jobs := parser.CountJobs(doc.Root)
		for _, format := range formats {
			if err := writeOutput(io.Discard, format, findings, nil, nil, jobs, true, true, true); err != nil {
				t.Fatalf("%s: %v", format, err)
			}
		}
	})
}
