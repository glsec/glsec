package parser

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func includeOf(t *testing.T, src string) *yaml.Node {
	t.Helper()
	doc, err := Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return FindKey(doc.MappingNode(), "include")
}

func TestIncludeItems(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string // "key=value" per item
	}{
		{"string remote", "include: https://example.com/ci.yml\n", []string{"remote=https://example.com/ci.yml"}},
		{"string local", "include: ci/build.yml\n", []string{"local=ci/build.yml"}},
		{"uppercase scheme", "include: HTTP://example.com/ci.yml\n", []string{"remote=HTTP://example.com/ci.yml"}},
		{"single mapping", "include:\n  project: a/b\n  file: x.yml\n", []string{"project=a/b"}},
		{"mixed list", "include:\n  - http://example.com/a.yml\n  - b.yml\n  - template: Auto-DevOps.gitlab-ci.yml\n",
			[]string{"remote=http://example.com/a.yml", "local=b.yml", "template=Auto-DevOps.gitlab-ci.yml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items := IncludeItems(includeOf(t, tc.src))
			if len(items) != len(tc.want) {
				t.Fatalf("got %d items, want %d", len(items), len(tc.want))
			}
			for i, item := range items {
				got := item.Content[0].Value + "=" + item.Content[1].Value
				if got != tc.want[i] {
					t.Errorf("item %d = %s, want %s", i, got, tc.want[i])
				}
			}
		})
	}
	if IncludeItems(nil) != nil {
		t.Error("expected nil for a missing include:")
	}
}

func TestIncludeItems_ShorthandKeepsPosition(t *testing.T) {
	items := IncludeItems(includeOf(t, "include:\n  - https://example.com/ci.yml\n"))
	if v := items[0].Content[1]; v.Line != 2 || v.Column != 5 {
		t.Errorf("value position = %d:%d, want 2:5", v.Line, v.Column)
	}
}
