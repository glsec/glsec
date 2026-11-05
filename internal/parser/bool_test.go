// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBool(t *testing.T) {
	for _, tc := range []struct {
		src       string
		value, ok bool
	}{
		{"true", true, true},
		{"True", true, true},
		{"TRUE", true, true},
		{"yes", true, true},
		{"Yes", true, true},
		{"on", true, true},
		{"ON", true, true},
		{"false", false, true},
		{"False", false, true},
		{"no", false, true},
		{"No", false, true},
		{"off", false, true},
		{"OFF", false, true},
		{`"yes"`, false, false},
		{`'true'`, false, false},
		{`"false"`, false, false},
		{"!!str yes", false, false},
		{"y", false, false},
		{"n", false, false},
		{"1", false, false},
		{"maybe", false, false},
		{"[yes]", false, false},
		{"", false, false},
	} {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte("v: "+tc.src+"\n"), &doc); err != nil {
			t.Fatal(err)
		}
		n := doc.Content[0].Content[1]
		value, ok := Bool(n)
		if value != tc.value || ok != tc.ok {
			t.Errorf("Bool(%s) = %v, %v, want %v, %v", tc.src, value, ok, tc.value, tc.ok)
		}
		if IsTrue(n) != (tc.ok && tc.value) || IsFalse(n) != (tc.ok && !tc.value) {
			t.Errorf("IsTrue/IsFalse(%s) disagree with Bool", tc.src)
		}
	}
	if _, ok := Bool(nil); ok {
		t.Error("Bool(nil) ok")
	}
}
