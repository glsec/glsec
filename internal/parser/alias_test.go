package parser

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseExpanded(t *testing.T, src string) *yaml.Node {
	t.Helper()
	doc, err := Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc.MappingNode()
}

func scalars(node *yaml.Node) []string {
	var out []string
	for _, n := range node.Content {
		out = append(out, n.Value)
	}
	return out
}

func TestExpandAliases_ScalarAndMapping(t *testing.T) {
	m := parseExpanded(t, `.img: &img node:latest
.c: &c
  key: deps
job:
  image: *img
  cache: *c
`)
	job := FindKey(m, "job")
	if img := FindKey(job, "image"); img == nil || img.Value != "node:latest" || img.Line != 1 {
		t.Errorf("image: expected node:latest at the anchor's line, got %+v", img)
	}
	if key := FindKey(FindKey(job, "cache"), "key"); key == nil || key.Value != "deps" {
		t.Error("cache: expected the anchored mapping")
	}
}

func TestExpandAliases_ListSplicing(t *testing.T) {
	m := parseExpanded(t, `.setup: &setup
  - apt-get update
  - apt-get install -y curl
job:
  script:
    - *setup
    - make
  after: *setup
`)
	job := FindKey(m, "job")
	got := scalars(FindKey(job, "script"))
	want := []string{"apt-get update", "apt-get install -y curl", "make"}
	if len(got) != len(want) {
		t.Fatalf("script = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("script[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if after := FindKey(job, "after"); after == nil || after.Kind != yaml.SequenceNode || len(after.Content) != 2 {
		t.Error("a list alias as a mapping value must stay a list")
	}
}

func TestExpandAliases_MergeKeys(t *testing.T) {
	m := parseExpanded(t, `.a: &a
  x: from-a
  y: from-a
.b: &b
  y: from-b
  z: from-b
job:
  <<: [*a, *b]
  x: own
single:
  <<: *b
quoted:
  '<<': literal
`)
	job := FindKey(m, "job")
	for key, want := range map[string]string{"x": "own", "y": "from-a", "z": "from-b"} {
		if got := FindKey(job, key); got == nil || got.Value != want {
			t.Errorf("job.%s: got %v, want %s", key, got, want)
		}
	}
	if FindKey(job, "<<") != nil {
		t.Error("the merge key must be folded away")
	}
	if got := FindKey(FindKey(m, "single"), "z"); got == nil || got.Value != "from-b" {
		t.Error("expected a single merge source to be folded in")
	}
	if got := FindKey(FindKey(m, "quoted"), "<<"); got == nil || got.Value != "literal" {
		t.Error("a quoted '<<' key is a plain string, not a merge key")
	}
}

func TestExpandAliases_NestedMerge(t *testing.T) {
	m := parseExpanded(t, `.base: &base
  image: node:latest
.mid: &mid
  <<: *base
  stage: test
job:
  <<: *mid
  script: [make]
`)
	job := FindKey(m, "job")
	if FindKey(job, "image") == nil || FindKey(job, "stage") == nil {
		t.Error("expected keys merged through two levels of anchors")
	}
}

// walkCapped counts the nodes a recursive walk visits, giving up past limit,
// so a regression to a cyclic or exploding tree fails instead of hanging.
func walkCapped(node *yaml.Node, limit int) int {
	n := 0
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if n > limit {
			return
		}
		n++
		if node.Kind == yaml.AliasNode {
			return
		}
		for _, c := range node.Content {
			walk(c)
		}
	}
	walk(node)
	return n
}

func TestExpandAliases_SelfReferenceStaysAlias(t *testing.T) {
	for name, src := range map[string]string{
		"alias to an ancestor": ".t: &t\n  job:\n    script: *t\n",
		"merge of an ancestor": ".a: &a\n  b:\n    <<: *a\n    x: 1\njob:\n  <<: *a\n  script: [echo]\n",
		"list item alias":      ".l: &l\n  - a\n  - *l\n",
	} {
		doc, err := Parse([]byte(src), "test.yml")
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if n := walkCapped(doc.Root, 10_000); n > 10_000 {
			t.Errorf("%s: expansion produced a cyclic tree", name)
		}
	}
}

func TestExpandAliases_MergeOfAncestorKeepsSiblingKeys(t *testing.T) {
	m := parseExpanded(t, ".a: &a\n  b:\n    <<: *a\n    x: 1\njob:\n  <<: *a\n  script: [echo]\n")
	b := FindKey(FindKey(m, "job"), "b")
	if b == nil || FindKey(b, "x") == nil {
		t.Error("expected job to merge .a, keeping b's own keys")
	}
}

func TestExpandAliases_NestedAliasBudget(t *testing.T) {
	var src strings.Builder
	src.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i <= 7; i++ {
		fmt.Fprintf(&src, "a%d: &a%d [", i, i)
		for j := 0; j < 10; j++ {
			if j > 0 {
				src.WriteString(", ")
			}
			fmt.Fprintf(&src, "*a%d", i-1)
		}
		src.WriteString("]\n")
	}
	src.WriteString("job:\n  script: *a7\n")
	doc, err := Parse([]byte(src.String()), "test.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	limit := 2 * maxExpandedNodes
	if n := walkCapped(doc.Root, limit); n > limit {
		t.Errorf("expanded tree exceeds the budget: more than %d nodes", limit)
	}
}
