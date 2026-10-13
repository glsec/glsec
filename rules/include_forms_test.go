package rules

import (
	"slices"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

// Every include rule must see the string and single-mapping forms of include:,
// not only a list of mappings.
func TestIncludeForms(t *testing.T) {
	GL075.SetAllowedIncludeSources([]string{"trusted.example.com"})
	defer GL075.SetAllowedIncludeSources(nil)

	cases := []struct {
		name  string
		src   string
		rules []string
	}{
		{"string remote", "include: https://evil.example.com/ci.yml\n", []string{"GL003", "GL075"}},
		{"string http in list", "include:\n  - http://evil.example.com/ci.yml\n", []string{"GL003", "GL016", "GL075"}},
		{"mapping remote http", "include:\n  remote: http://evil.example.com/ci.yml\n", []string{"GL003", "GL016", "GL075"}},
		{"mapping component main", "include:\n  component: gitlab.com/org/comp/a@main\n", []string{"GL003", "GL041", "GL075"}},
		{"mapping project no ref", "include:\n  project: org/templates\n  file: /ci.yml\n", []string{"GL003", "GL075"}},
		{"mapping local var", "include:\n  local: $TEMPLATE.yml\n", []string{"GL084"}},
		{"string local", "include: ci/build.yml\n", nil},
	}
	all := []string{"GL003", "GL016", "GL041", "GL075", "GL084"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.src+"build:\n  script: [make]\n"), "test.yml")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			want := map[string]bool{}
			for _, id := range tc.rules {
				want[id] = true
			}
			for _, r := range All() {
				id := r.ID()
				if !slices.Contains(all, id) {
					continue
				}
				got := len(Check(r, doc, "test.yml")) > 0
				if got != want[id] {
					t.Errorf("%s: fired=%v, want %v", id, got, want[id])
				}
			}
		})
	}
}
