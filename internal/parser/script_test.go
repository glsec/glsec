// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// commands returns the values and lines of the items of a script list.
func commands(t *testing.T, n *yaml.Node) (values []string, lines []int) {
	t.Helper()
	if n == nil || n.Kind != yaml.SequenceNode {
		t.Fatalf("got %v, want a sequence", n)
	}
	for _, item := range n.Content {
		if item.Kind != yaml.ScalarNode {
			t.Fatalf("item %v is not a command", item)
		}
		values = append(values, item.Value)
		lines = append(lines, item.Line)
	}
	return values, lines
}

func TestNormalizeScripts(t *testing.T) {
	doc, err := Parse([]byte(`before_script: echo top
default:
  after_script: echo default
  hooks:
    pre_get_sources_script: echo hook
variables:
  script: not a command
string:
  script: echo one
nested:
  script:
    - echo a
    - - echo b
      - - echo c
    - echo d
.hidden:
  before_script: echo hidden
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	top := doc.MappingNode()
	tests := []struct {
		node  *yaml.Node
		want  []string
		lines []int
	}{
		{FindKey(top, "before_script"), []string{"echo top"}, []int{1}},
		{FindKey(FindKey(top, "default"), "after_script"), []string{"echo default"}, []int{3}},
		{FindKey(FindKey(FindKey(top, "default"), "hooks"), "pre_get_sources_script"), []string{"echo hook"}, []int{5}},
		{FindKey(FindKey(top, "string"), "script"), []string{"echo one"}, []int{9}},
		{FindKey(FindKey(top, "nested"), "script"), []string{"echo a", "echo b", "echo c", "echo d"}, []int{12, 13, 14, 15}},
		{FindKey(FindKey(top, ".hidden"), "before_script"), []string{"echo hidden"}, []int{17}},
	}
	for _, tt := range tests {
		got, lines := commands(t, tt.node)
		if strings.Join(got, "|") != strings.Join(tt.want, "|") {
			t.Errorf("got %q, want %q", got, tt.want)
		}
		for i := range lines {
			if lines[i] != tt.lines[i] {
				t.Errorf("%q: line %d, want %d", got[i], lines[i], tt.lines[i])
			}
		}
	}
	if v := FindKey(FindKey(top, "variables"), "script"); v.Kind != yaml.ScalarNode {
		t.Errorf("a variable named script was turned into a %v", v.Kind)
	}
}

func TestNormalizeScripts_UnresolvedReferenceKept(t *testing.T) {
	doc, err := Parse([]byte("job:\n  script:\n    - !reference [.from-include, script]\n    - echo hi\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	script := FindKey(FindKey(doc.MappingNode(), "job"), "script")
	if len(script.Content) != 2 || !isReference(script.Content[0]) {
		t.Errorf("an unresolved !reference was flattened into the script: %v", script.Content)
	}
}

func TestNormalizeScripts_NestingCap(t *testing.T) {
	src := "job:\n  script: " + strings.Repeat("[", 50) + "echo deep" + strings.Repeat("]", 50) + "\n"
	if _, err := Parse([]byte(src), "test.yml"); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeScripts_UnresolvedReferenceStays(t *testing.T) {
	doc, err := Parse([]byte(`
build:
  script: !reference [.from_include, script]
  before_script:
    - - echo nested
      - !reference [.from_include, before_script]
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	job := FindKey(doc.MappingNode(), "build")
	script := FindKey(job, "script")
	if !isReference(script) || len(script.Content) != 2 || script.Content[0].Value != ".from_include" {
		t.Errorf("an unresolved !reference as the whole script: must stay a reference, got kind %d tag %q", script.Kind, script.Tag)
	}
	before := FindKey(job, "before_script").Content
	if len(before) != 2 || before[0].Value != "echo nested" || !isReference(before[1]) {
		t.Errorf("flattening must keep a nested unresolved !reference as one item, got %v", before)
	}
}

func TestNormalizeScripts_Hooks(t *testing.T) {
	doc, err := Parse([]byte(`
string_hooks:
  hooks: not a mapping
  script: [make]
other_hooks:
  hooks:
    pre_get_sources_script: echo hook
    other_hook: echo untouched
  script: [make]
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	top := doc.MappingNode()
	if h := FindKey(FindKey(top, "string_hooks"), "hooks"); h.Kind != yaml.ScalarNode || h.Value != "not a mapping" {
		t.Errorf("hooks: that isn't a mapping must stay as it is, got kind %d", h.Kind)
	}
	hooks := FindKey(FindKey(top, "other_hooks"), "hooks")
	if values, _ := commands(t, FindKey(hooks, "pre_get_sources_script")); len(values) != 1 || values[0] != "echo hook" {
		t.Errorf("pre_get_sources_script = %v", values)
	}
	if other := FindKey(hooks, "other_hook"); other.Kind != yaml.ScalarNode {
		t.Errorf("only pre_get_sources_script is a script list, other_hook became kind %d", other.Kind)
	}
}
