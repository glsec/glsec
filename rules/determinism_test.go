// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

// Every rule gives the same findings in the same order on every run. Go
// randomises map iteration, so a rule that walks a map to build its findings
// fails here once a fixture or corpus file gives it more than one (#1081).
func TestRulesAreDeterministic(t *testing.T) {
	var files []string
	for _, pattern := range []string{"../testdata/fixtures/*.yml", "../testdata/corpus/*.yml"} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 50 {
		t.Fatalf("found %d input files, want the fixtures and the regression corpus", len(files))
	}
	const runs = 30
	for _, path := range files {
		src, err := os.ReadFile(path) //nolint:gosec // test reads its own fixtures
		if err != nil {
			t.Fatal(err)
		}
		doc, err := parser.Parse(src, path)
		if err != nil {
			continue // fixtures for parse errors
		}
		for _, r := range All() {
			first := Check(r, doc, path)
			for i := 1; i < runs; i++ {
				if got := Check(r, doc, path); !reflect.DeepEqual(got, first) {
					t.Errorf("%s on %s: run %d differs from run 1:\n%v\nvs\n%v", r.ID(), filepath.Base(path), i+1, got, first)
					break
				}
			}
		}
	}
}

// Findings that share one line come in the order spec:inputs declares the
// inputs. GL051's old map order gave one order in about 80 % of runs, so 30
// runs miss it in under 0.2 % of test runs.
func TestGL051_FindingsInDeclarationOrder(t *testing.T) {
	src := `spec:
  inputs:
    zeta: {}
    alpha: {}
    mid: {}
---
job:
  script:
    - ./run $[[ inputs.alpha ]] $[[ inputs.mid ]] $[[ inputs.zeta ]]
`
	doc, err := parser.Parse([]byte(src), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		var names []string
		for _, f := range Check(GL051, doc, "t.yml") {
			names = append(names, f.Message[33:38])
		}
		if want := []string{`zeta"`, `alpha`, `mid" `}; !reflect.DeepEqual(names, want) {
			t.Fatalf("run %d: got %q, want %q", i+1, names, want)
		}
	}
}
