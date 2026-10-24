// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/validate"
)

// docExample is one YAML block from a rule's documentation.
type docExample struct {
	line    int
	trigger bool
	src     string
}

// docExamples returns the YAML blocks under the "Trigger example(s)" and
// "Safe alternative(s)" headings of a rule doc. Blocks under any other
// heading are not checked: they illustrate notes, partial snippets or
// configuration files.
func docExamples(doc string) []docExample {
	var out []docExample
	var section string
	lines := strings.Split(doc, "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l, "## ") {
			h := strings.ToLower(strings.TrimPrefix(l, "## "))
			switch {
			case strings.HasPrefix(h, "trigger example"):
				section = "trigger"
			case strings.HasPrefix(h, "safe alternative"):
				section = "safe"
			default:
				section = ""
			}
			continue
		}
		if l != "```yaml" && l != "```yml" {
			continue
		}
		start := i + 1
		for i++; i < len(lines) && !strings.HasPrefix(lines[i], "```"); i++ {
		}
		if section != "" {
			out = append(out, docExample{
				line:    start,
				trigger: section == "trigger",
				src:     strings.Join(lines[start:i], "\n") + "\n",
			})
		}
	}
	return out
}

// TestDocExamples checks that every trigger example in docs/rules makes its
// rule fire and no safe alternative does (#696). An example glsec rejects as a
// pipeline file fails too, since nobody could try it.
func TestDocExamples(t *testing.T) {
	for _, r := range All() {
		id := r.ID()
		path := filepath.Join("..", "docs", "rules", id+".md")
		data, err := os.ReadFile(path) //nolint:gosec // G304: test reads known-safe local paths
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		examples := docExamples(string(data))
		if len(examples) == 0 {
			continue
		}
		t.Run(id, func(t *testing.T) {
			sawTrigger := false
			for _, ex := range examples {
				sawTrigger = sawTrigger || ex.trigger
				doc, err := parser.Parse([]byte(ex.src), ".gitlab-ci.yml")
				if err == nil {
					_, err = validate.File(".gitlab-ci.yml", doc)
				}
				if err != nil {
					t.Errorf("docs/rules/%s.md:%d: glsec rejects the example: %v", id, ex.line, err)
					continue
				}
				// Inline suppressions are applied by the CLI, not by Check.
				if strings.Contains(ex.src, "glsec:ignore "+id) {
					continue
				}
				n := len(Check(r, doc, ".gitlab-ci.yml"))
				switch {
				case ex.trigger && n == 0:
					t.Errorf("docs/rules/%s.md:%d: trigger example produces no %s finding", id, ex.line, id)
				case !ex.trigger && n > 0:
					t.Errorf("docs/rules/%s.md:%d: safe alternative produces %d %s finding(s)", id, ex.line, n, id)
				}
			}
			if !sawTrigger {
				t.Errorf("docs/rules/%s.md has safe alternatives but no YAML trigger example", id)
			}
		})
	}
}
