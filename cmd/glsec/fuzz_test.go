// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
	gitlabver "github.com/glsec/glsec/internal/version"
	"github.com/glsec/glsec/rules"
)

// fuzzFormats is every report format. FormatTemplate renders fuzzTemplate.
var fuzzFormats = []output.Format{
	output.FormatText, output.FormatTable, output.FormatJSON,
	output.FormatSARIF, output.FormatCodeClimate, output.FormatJUnit,
	output.FormatGitLabSAST, output.FormatTemplate,
}

var fuzzTemplate = template.Must(template.New("report").Parse(
	"{{.Version}} {{.Summary.Error}} {{.Summary.Files}} {{.Summary.Jobs}}\n" +
		"{{range .Findings}}{{.Rule}} {{.Severity}} {{.File}}:{{.Line}} {{.Job}} {{.Message}}\n{{end}}" +
		"{{range .Errors}}{{.File}} {{.Message}}\n{{end}}"))

// fuzzReport renders one scan result in every format.
func fuzzReport(t *testing.T, findings []finding.Finding, suppressed []finding.Suppressed, errs []output.ScanError, jobs int, sources map[string][]byte) {
	t.Helper()
	tmpl := output.WithTemplate(fuzzTemplate, output.TemplateMeta{
		Version: "fuzz", Files: len(sources),
		OWASP: rules.OWASPCategories, ASVS: rules.ASVSRequirements,
	})
	for _, format := range fuzzFormats {
		if err := writeOutput(io.Discard, format, findings, suppressed, errs, jobs, true, true, true, tmpl, output.WithSources(sources)); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
	}
}

// FuzzScan takes one document through the rules and every report format:
// parse, collect findings with inline suppressions, render. FuzzScanGraph
// covers what happens around it.
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
	// No fixture carries a suppression.
	f.Add([]byte("job:\n  image: node:latest # glsec:ignore GL001 -- pinned by the base image\n  script: [make]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := parser.Parse(data, "fuzz.yml")
		if err != nil {
			return
		}
		findings, suppressed, _, err := collectFindings(doc, "fuzz.yml", config.Default(), gitlabver.Version{}, false, true)
		if err != nil {
			t.Fatalf("collectFindings: %v", err)
		}
		fuzzReport(t, findings, suppressed, nil, parser.CountJobs(doc.Root), map[string][]byte{"fuzz.yml": data})
	})
}

// The file names of a FuzzScanGraph input. They are fixed, so that an input
// can only name files that exist by spelling them, and the size of a graph is
// bounded: four files of at most fuzzGraphMaxFile bytes each.
const (
	fuzzGraphRoot    = ".gitlab-ci.yml"
	fuzzGraphA       = "a.yml"
	fuzzGraphB       = "b.yml"
	fuzzGraphChild   = "child.yml"
	fuzzGraphMaxFile = 16 << 10
)

// fuzzGraphSeeds are the shapes of a file graph; docs and suppressed are how
// many files a scan of the seed reads and how many findings it suppresses.
var fuzzGraphSeeds = []struct {
	name          string
	root, a, b, c string
	docs          int
	suppressed    int
}{
	{
		name: "shared include",
		root: "include:\n  - local: a.yml\n  - local: b.yml\njob:\n  extends: .base\n  script: [make]\n",
		a:    "include:\n  - local: child.yml\na-job:\n  extends: .base\n  script: [make]\n",
		b:    "include:\n  - local: child.yml\nb-job:\n  extends: .base\n  script: [make]\n",
		c:    ".base:\n  image: node:latest\n",
		docs: 4,
	},
	{
		name: "include cycle",
		root: "include:\n  - local: a.yml\njob:\n  script: [make]\n",
		a:    "include:\n  - local: b.yml\na-job:\n  script: [make]\n",
		b:    "include:\n  - local: a.yml\n  - local: .gitlab-ci.yml\nb-job:\n  script: [make]\n",
		docs: 3,
	},
	{
		name: "child pipeline cycle",
		root: "trigger-job:\n  trigger:\n    include: child.yml\n",
		c:    "trigger-job:\n  trigger:\n    include: child.yml\nback:\n  trigger:\n    include: .gitlab-ci.yml\n",
		docs: 2,
	},
	{
		name: "independent child pipelines",
		root: "default:\n  image: alpine:3.20\nfirst:\n  trigger:\n    include: a.yml\nsecond:\n  trigger:\n    include: child.yml\n",
		a:    "job:\n  image: node:latest\n  script: [make]\n",
		c:    "job:\n  script: [make]\n",
		docs: 3,
	},
	{
		name: "child and include share a file",
		root: "include:\n  - local: a.yml\nrun-child:\n  trigger:\n    include: a.yml\n",
		a:    "job:\n  script: [make]\n",
		docs: 2,
	},
	{
		name: "conflicting configuration",
		root: "include:\n  - local: a.yml\n  - local: b.yml\nvariables:\n  GIT_STRATEGY: fetch\ndefault:\n  image: alpine:3.20\njob:\n  image: node:latest\n  script: [make]\n",
		a:    "variables:\n  GIT_STRATEGY: none\ndefault:\n  image: node:latest\njob:\n  image: alpine:3.20\n  script: [lint]\n",
		b:    "variables:\n  GIT_STRATEGY: clone\ndefault:\n  image: python:latest\n.hidden:\n  script: [echo]\n",
		docs: 3,
	},
	{
		name: "suppression in an include",
		root: "include:\n  - local: a.yml\njob:\n  script: [make]\n",
		a:    "other:\n  image: node:latest # glsec:ignore GL001 -- pinned by the base image\n  script: [make]\n",
		docs: 2, suppressed: 1,
	},
	{
		name: "unreadable and escaping paths",
		root: "include:\n  - local: missing.yml\n  - local: ../outside.yml\n  - local: '*.yml'\njob:\n  script: [make]\n",
		a:    "not: [valid\n",
		docs: 1,
	},
}

// fuzzGraphScan writes the files to a temporary directory and scans them the
// way a run does. With the default configuration ShellCheck stays off, and
// newOnly leaves out .glsec-ignore: the file is read from the working
// directory, not the temporary one.
func fuzzGraphScan(t *testing.T, root, a, b, child []byte) (findings []finding.Finding, suppressed []finding.Suppressed, jobs int, scanErr *output.ScanError, sources map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string][]byte{fuzzGraphRoot: root, fuzzGraphA: a, fuzzGraphB: b, fuzzGraphChild: child} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sources = map[string][]byte{}
	findings, suppressed, jobs, _, scanErr = scanRoot(filepath.Join(dir, fuzzGraphRoot), scanOptions{
		stderr:       io.Discard,
		cfg:          config.Default(),
		scannedFiles: map[string]bool{},
		included:     map[string]bool{},
		sources:      sources,
		newOnly:      true,
	})
	return findings, suppressed, jobs, scanErr, sources
}

// FuzzScanGraph runs small file graphs through the production scan path:
// file validation, following includes and child pipelines, pipeline context,
// rules and every report format. CONTRIBUTING.md lists what stays outside.
func FuzzScanGraph(f *testing.F) {
	for _, s := range fuzzGraphSeeds {
		f.Add([]byte(s.root), []byte(s.a), []byte(s.b), []byte(s.c))
	}
	f.Fuzz(func(t *testing.T, root, a, b, child []byte) {
		for _, data := range [][]byte{root, a, b, child} {
			if len(data) > fuzzGraphMaxFile {
				return
			}
		}
		findings, suppressed, jobs, scanErr, sources := fuzzGraphScan(t, root, a, b, child)
		var errs []output.ScanError
		if scanErr != nil {
			errs = []output.ScanError{*scanErr}
		}
		fuzzReport(t, findings, suppressed, errs, jobs, sources)
	})
}

// A seed the scan rejects, or that doesn't reach its files, would leave the
// fuzzer without the shape it is there for.
func TestFuzzGraphSeeds(t *testing.T) {
	for _, s := range fuzzGraphSeeds {
		t.Run(s.name, func(t *testing.T) {
			_, suppressed, _, scanErr, sources := fuzzGraphScan(t, []byte(s.root), []byte(s.a), []byte(s.b), []byte(s.c))
			if scanErr != nil {
				t.Fatalf("scan failed: %s", scanErr.Message)
			}
			if len(sources) != s.docs {
				t.Errorf("read %d files, want %d: %v", len(sources), s.docs, sources)
			}
			if len(suppressed) != s.suppressed {
				t.Errorf("%d suppressed findings, want %d", len(suppressed), s.suppressed)
			}
		})
	}
}
