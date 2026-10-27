// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateCorpus = flag.Bool("update", false, "rewrite the testdata/corpus snapshots")

// TestCorpus scans each pipeline in testdata/corpus, short excerpts from past
// false-positive and false-negative issues, and compares the findings with
// the .golden snapshot next to it (#838). A finding that appears or
// disappears fails the test; after an intended change, run
//
//	go test ./cmd/glsec -run TestCorpus -update
//
// and review the snapshot diff.
func TestCorpus(t *testing.T) {
	// Absolute, since runCLI changes into a temporary directory.
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no pipelines in testdata/corpus")
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".yml")
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(path) //nolint:gosec // G304: test reads the repository's own corpus
			if err != nil {
				t.Fatal(err)
			}
			got := corpusFindings(t, string(src))
			golden := strings.TrimSuffix(path, ".yml") + ".golden"
			if *updateCorpus {
				if err := os.WriteFile(golden, []byte(got), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden) //nolint:gosec // G304: snapshot next to the corpus file
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			// Git may check the snapshot out with CRLF line endings on Windows.
			if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Errorf("findings differ from %s (run with -update after an intended change)\ngot:\n%swant:\n%s", filepath.Base(golden), got, want)
			}
		})
	}
}

// corpusFindings scans src as .gitlab-ci.yml and returns one line per
// finding, "LINE RULE SEVERITY JOB", sorted by line.
func corpusFindings(t *testing.T, src string) string {
	t.Helper()
	code, stdout, stderr := runCLI(t, map[string]string{".gitlab-ci.yml": src},
		"--no-cache", "--no-repo-config", "--format", "json", ".gitlab-ci.yml")
	if code == 2 {
		t.Fatalf("exit 2: %s", stderr)
	}
	var out struct {
		Findings []struct {
			Rule     string `json:"rule"`
			Severity string `json:"severity"`
			Job      string `json:"job"`
			Line     int    `json:"line"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("parse JSON output: %v", err)
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule+a.Job < b.Rule+b.Job
	})
	lines := make([]string, 0, len(out.Findings))
	for _, f := range out.Findings {
		job := f.Job
		if job == "" {
			job = "-"
		}
		lines = append(lines, fmt.Sprintf("%d %s %s %s", f.Line, f.Rule, f.Severity, job))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
