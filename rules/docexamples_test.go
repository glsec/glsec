// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
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
	doc = strings.ReplaceAll(doc, "\r\n", "\n")
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

// noDocExamples lists rules whose docs intentionally have no executable YAML
// block under Trigger example(s) / Safe alternative(s).
var noDocExamples = map[string]string{
	"GL075": "opt-in rule requiring allowed_include_sources in .glsec.yml",
	"GL078": "raw-byte Unicode control character rule; trigger example is a text block",
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
			if _, ok := noDocExamples[id]; !ok {
				t.Errorf("docs/rules/%s.md has no executable YAML example under Trigger example(s) or Safe alternative(s)", id)
			}
			continue
		}
		if reason, ok := noDocExamples[id]; ok {
			t.Errorf("docs/rules/%s.md now has %d example(s); remove it from noDocExamples (%s)", id, len(examples), reason)
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
				// A script line read as a mapping or a duplicate key is a slip in
				// any example except the trigger examples of the rules about them.
				for _, s := range []rule.Rule{GL086, GL087} {
					if s.ID() == id {
						continue
					}
					for _, f := range Check(s, doc, ".gitlab-ci.yml") {
						t.Errorf("docs/rules/%s.md:%d: example trips %s: %s", id, ex.line+f.Line, s.ID(), f.Message)
					}
				}
				n := len(Check(r, doc, ".gitlab-ci.yml"))
				// Inline suppressions are applied by the CLI, not by Check;
				// verify the underlying rule still fires on the unsuppressed YAML
				// (CLI suppression is verified in cmd/glsec).
				if strings.Contains(ex.src, "glsec:ignore "+id) {
					if n == 0 {
						t.Errorf("docs/rules/%s.md:%d: glsec:ignore example produces no %s finding even without suppression", id, ex.line, id)
					}
					continue
				}
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

func TestDocExamples_CRLF(t *testing.T) {
	doc := "## Trigger example\r\n\r\n```yaml\r\njob:\r\n  script: echo hi\r\n```\r\n\r\n## Safe alternative\r\n\r\n```yml\r\njob:\r\n  script: echo safe\r\n```\r\n"
	got := docExamples(doc)
	if len(got) != 2 {
		t.Fatalf("got %d examples, want 2: %+v", len(got), got)
	}
	if !got[0].trigger || got[0].src != "job:\n  script: echo hi\n" {
		t.Errorf("unexpected trigger example: %+v", got[0])
	}
	if got[1].trigger || got[1].src != "job:\n  script: echo safe\n" {
		t.Errorf("unexpected safe example: %+v", got[1])
	}
}
