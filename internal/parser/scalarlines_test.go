// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func scalarAt(t *testing.T, src string, path ...string) *yaml.Node {
	t.Helper()
	doc, err := Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	n := doc.MappingNode()
	for _, key := range path {
		n = FindKey(n, key)
		if n == nil {
			t.Fatalf("no %q in %s", key, src)
		}
	}
	return n
}

// lineOf returns the source line ScalarOffsetLine gives for the first
// occurrence of word in the node's value.
func lineOf(t *testing.T, n *yaml.Node, word string) int {
	t.Helper()
	off := strings.Index(n.Value, word)
	if off < 0 {
		t.Fatalf("%q not in %q", word, n.Value)
	}
	return ScalarOffsetLine(n, off)
}

func TestScalarOffsetLine(t *testing.T) {
	for _, tc := range []struct {
		name, src, word string
		want            int
	}{
		{"plain, folded line", "a:\n  b: one\n    two\n    three\n", "three", 4},
		{"plain, blank line", "a:\n  b: one\n\n\n    two\n", "two", 5},
		{"plain, first word", "a:\n  b: one\n    two\n", "one", 2},
		{"CRLF", "a:\r\n  b: one\r\n    two\r\n", "two", 3},
		{"lone CR", "a:\r  b: one\r    two\r", "two", 3},
		{"tabs", "a:\n  b: one\n    \ttwo\n", "two", 3},
		{"non-ASCII before the scalar", "a:\n  b: [äöü, \"one\n    two\"]\n", "two", 3},
		{"single-quoted", "a:\n  b: 'one\n    two'\n", "two", 3},
		{"single-quoted with an escape", "a:\n  b: 'it''s\n    two'\n", "two", 2},
		{"double-quoted", "a:\n  b: \"one\n\n    two\"\n", "two", 4},
		{"double-quoted with an escape", "a:\n  b: \"one\\t\n    two\"\n", "two", 2},
		{"folded block", "a:\n  b: >\n    one\n    two\n\n    three\n", "three", 6},
		{"folded block, more indented", "a:\n  b: >-\n    one\n      two\n    three\n", "three", 5},
		{"literal block", "a:\n  b: |\n    one\n    two\n", "two", 4},
		{"flow sequence item", "a:\n  b: [\"x\", \"one\n    two\"]\n", "two", 3},
		{"one line", "a:\n  b: one two\n", "two", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := scalarAt(t, tc.src, "a", "b")
			if n.Kind == yaml.SequenceNode {
				n = n.Content[len(n.Content)-1]
			}
			if got := lineOf(t, n, tc.word); got != tc.want {
				t.Errorf("line of %q = %d, want %d", tc.word, got, tc.want)
			}
		})
	}
}

func TestScalarOffsetLine_Whitespace(t *testing.T) {
	n := scalarAt(t, "a:\n  b: one\n    two\n", "a", "b")
	// The space folded from the line break belongs to the line after it.
	if got := ScalarOffsetLine(n, strings.Index(n.Value, " ")); got != 3 {
		t.Errorf("line of the folded space = %d, want 3", got)
	}
	if got := ScalarOffsetLine(n, len(n.Value)+5); got != 3 {
		t.Errorf("line past the end = %d, want 3", got)
	}
}

// An alias and a !reference copy report the lines of the original.
func TestScalarOffsetLine_AliasAndReference(t *testing.T) {
	src := `.base:
  script: &s
    - echo one
      echo two
build:
  script: *s
deploy:
  script:
    - !reference [.base, script]
`
	for _, job := range []string{"build", "deploy"} {
		n := scalarAt(t, src, job, "script").Content[0]
		if got := lineOf(t, n, "two"); got != 4 {
			t.Errorf("%s: line of %q = %d, want 4", job, "two", got)
		}
	}
}

func TestScalarOffsetLine_NodeBuiltAfterParsing(t *testing.T) {
	n := &yaml.Node{Kind: yaml.ScalarNode, Value: "one two", Line: 7}
	if got := ScalarOffsetLine(n, 4); got != 7 {
		t.Errorf("line = %d, want the node's own line 7", got)
	}
}
