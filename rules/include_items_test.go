// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

const triggerIncludes = `child:
  trigger:
    include:
      - project: other/group
        file: /child.yml
      - component: gitlab.com/acme/comp/build@main
      - remote: http://example.com/child.yml
`

func includeFindings(t *testing.T, src string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	var out []finding.Finding
	for _, r := range []interface {
		Check(*yaml.Node, string) []finding.Finding
	}{GL003, GL016, GL041} {
		out = append(out, r.Check(doc.Root, "test.yml")...)
	}
	return out
}

// trigger:include takes the same entries as include:, so the same rules apply
// at the same places (#1162).
func TestTriggerInclude_EntriesAreChecked(t *testing.T) {
	type at struct {
		rule string
		line int
	}
	want := map[at]int{{"GL003", 4}: 1, {"GL003", 6}: 1, {"GL003", 7}: 1, {"GL041", 6}: 1, {"GL016", 7}: 1}
	got := map[at]int{}
	for _, f := range includeFindings(t, triggerIncludes) {
		got[at{f.RuleID, f.Line}]++
		if f.Job != "child" {
			t.Errorf("%s: job %q, want child", f.RuleID, f.Job)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%v: got %d, want %d", k, got[k], n)
		}
	}
}

func TestTriggerInclude_Forms(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      int
	}{
		{"string shorthand", "job:\n  trigger:\n    include: child.yml\n", 0},
		{"local mapping", "job:\n  trigger:\n    include:\n      local: child.yml\n", 0},
		{"local in a list", "job:\n  trigger:\n    include:\n      - local: child.yml\n", 0},
		{"artifact", "job:\n  trigger:\n    include:\n      - artifact: gen.yml\n        job: gen\n", 0},
		{"other project", "job:\n  trigger: other/project\n", 0},
		{"multi-project mapping", "job:\n  trigger:\n    project: other/project\n", 0},
		{"URL shorthand", "job:\n  trigger:\n    include: https://example.com/c.yml\n", 1},
		{"single mapping", "job:\n  trigger:\n    include:\n      project: other/group\n      file: /c.yml\n", 1},
		{"pinned", "job:\n  trigger:\n    include:\n      - project: other/group\n        ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n        file: /c.yml\n", 0},
		{"variable", "job:\n  trigger:\n    include:\n      - local: ci/$FLAVOUR.yml\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := includeFindings(t, tc.src); len(f) != tc.want {
				t.Fatalf("got %v, want %d findings", f, tc.want)
			}
		})
	}
}

// A trigger:include in a template is checked once, in the template, however
// many jobs extend it or share it through an alias.
func TestTriggerInclude_InheritedOnce(t *testing.T) {
	const src = `.child: &child
  trigger:
    include:
      - project: other/group
        file: /c.yml
a:
  extends: .child
b:
  extends: .child
c: *child
`
	f := includeFindings(t, src)
	if len(f) != 1 || f[0].RuleID != "GL003" || f[0].Line != 4 || f[0].Job != ".child" {
		t.Fatalf("got %v, want one GL003 on the template's entry", f)
	}
}

func TestTriggerInclude_TopLevelStaysJobless(t *testing.T) {
	f := includeFindings(t, "include:\n  - project: other/group\n    file: /c.yml\njob:\n  script: [make]\n")
	if len(f) != 1 || f[0].Job != "" {
		t.Fatalf("got %v", f)
	}
}

// The variable expands in the child pipeline, usually to a value from this
// file, so GL084 stays with the top-level include: (#1162).
func TestTriggerInclude_VariableIsNotGL084(t *testing.T) {
	doc, err := parser.Parse([]byte("job:\n  parallel:\n    matrix:\n      - APP: [a, b]\n  trigger:\n    include: $APP/ci.yml\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if f := GL084.Check(doc.Root, "test.yml"); len(f) != 0 {
		t.Errorf("got %v", f)
	}
}
