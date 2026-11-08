// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const profile = `mode: atomic
github.com/glsec/glsec/rules/a.go:10.2,12.3 2 5
github.com/glsec/glsec/rules/a.go:13.2,15.3 2 0
github.com/glsec/glsec/rules/a.go:15.3,17.3 1 1
github.com/glsec/glsec/main.go:1.1,2.2 1 0
`

const diff = `diff --git a/rules/a.go b/rules/a.go
--- a/rules/a.go
+++ b/rules/a.go
@@ -9,0 +11,2 @@ func f() {
+a
+b
@@ -20 +14 @@ func g() {
+c
@@ -30 +30,0 @@ func h() {
-gone
diff --git a/new.go b/new.go
--- /dev/null
+++ b/new.go
@@ -0,0 +1 @@
+d
diff --git a/old.go b/old.go
--- a/old.go
+++ /dev/null
@@ -1 +0,0 @@
-e
`

func TestParseDiff(t *testing.T) {
	got, err := parseDiff(strings.NewReader(diff))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]int{"rules/a.go": {11, 12, 14}, "new.go": {1}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseProfile(t *testing.T) {
	got, err := parseProfile(strings.NewReader(profile), "github.com/glsec/glsec")
	if err != nil {
		t.Fatal(err)
	}
	if len(got["rules/a.go"]) != 3 || len(got["main.go"]) != 1 || !got["rules/a.go"][0].covered || got["main.go"][0].covered {
		t.Errorf("got %+v", got)
	}
	if _, err := parseProfile(strings.NewReader("nonsense\n"), ""); err == nil {
		t.Error("a bad line is an error")
	}
}

func TestCheck(t *testing.T) {
	blocks := map[string][]block{"a.go": {{10, 12, true}, {13, 15, false}, {15, 17, true}}}
	got := check(blocks, map[string][]int{"a.go": {9, 11, 14, 15}, "none.go": {1}})
	if got.covered != 2 || !reflect.DeepEqual(got.uncovered, []string{"a.go:14"}) {
		t.Errorf("a line outside any block doesn't count, one covered by either block does: %+v", got)
	}
}

func TestWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		r       result
		grace   int
		code    int
		message string
	}{
		{"nothing changed", result{}, 3, 0, "no changed statements"},
		{"all covered", result{covered: 5}, 3, 0, "100.0%"},
		{"at the minimum", result{covered: 8, uncovered: []string{"a", "b"}}, 0, 0, "80.0%"},
		{"below", result{covered: 7, uncovered: []string{"a", "b", "c"}}, 0, 1, "not covered: c"},
		{"small change in the grace", result{covered: 1, uncovered: []string{"a", "b", "c"}}, 3, 0, "25.0%"},
		{"past the grace", result{covered: 1, uncovered: []string{"a", "b", "c", "d"}}, 3, 1, "20.0%"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := tc.r.write(&out, 80, tc.grace); code != tc.code {
				t.Errorf("exit %d, want %d", code, tc.code)
			}
			if !strings.Contains(out.String(), tc.message) {
				t.Errorf("output %q lacks %q", out.String(), tc.message)
			}
		})
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	p, d := write("coverage.out", profile), write("change.diff", diff)
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"passes in the grace", []string{"-profile", p, "-diff", d}, 0},
		{"fails without it", []string{"-profile", p, "-diff", d, "-grace", "0", "-min", "90"}, 1},
		{"unknown flag", []string{"-nope"}, 2},
		{"missing profile", []string{"-profile", filepath.Join(dir, "x"), "-diff", d}, 2},
		{"missing diff", []string{"-profile", p, "-diff", filepath.Join(dir, "x")}, 2},
		{"bad profile", []string{"-profile", write("bad", "nonsense\n"), "-diff", d}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tc.args, &out, &errOut); code != tc.code {
				t.Errorf("exit %d, want %d: %s%s", code, tc.code, out.String(), errOut.String())
			}
		})
	}
}
