// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func scalarOf(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatalf("unmarshal %q: %v", src, err)
	}
	// Document → mapping → value of key "v"
	root := doc.Content[0]
	return root.Content[1]
}

func TestBool(t *testing.T) {
	cases := []struct {
		src   string
		value bool
		ok    bool
	}{
		{"v: true\n", true, true},
		{"v: True\n", true, true},
		{"v: yes\n", true, true},
		{"v: YES\n", true, true},
		{"v: on\n", true, true},
		{"v: false\n", false, true},
		{"v: no\n", false, true},
		{"v: Off\n", false, true},
		{"v: \"yes\"\n", false, false},
		{"v: 'yes'\n", false, false},
		{"v: !!str yes\n", false, false},
		{"v: y\n", false, false},
		{"v: n\n", false, false},
		{"v: 1\n", false, false},
		{"v: \n", false, false},
	}
	for _, tc := range cases {
		n := scalarOf(t, tc.src)
		got, ok := Bool(n)
		if ok != tc.ok || got != tc.value {
			t.Errorf("%q: got (%v, %v), want (%v, %v) style=%v tag=%q",
				tc.src, got, ok, tc.value, tc.ok, n.Style, n.Tag)
		}
	}
	if v, ok := Bool(nil); ok || v {
		t.Errorf("Bool(nil) = (%v, %v), want (false, false)", v, ok)
	}
	if v, ok := Bool(&yaml.Node{Kind: yaml.MappingNode}); ok || v {
		t.Errorf("Bool(mapping) = (%v, %v), want (false, false)", v, ok)
	}
}
