// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"
	"strings"
	"testing"
)

func TestLocalIncludePaths(t *testing.T) {
	doc := mustParse(t, `include:
  - local: ci/a.yml
  - /ci/b.yml
  - local: ci/$ENV.yml
  - remote: https://example.com/ci.yml
  - https://example.com/short.yml
  - project: group/project
    file: ci.yml
  - template: Jobs/SAST.gitlab-ci.yml
  - component: gitlab.com/group/c@1
  - local: ci/*.yml
    rules:
      - if: $CI_COMMIT_TAG
job:
  script: [x]
`)
	got := LocalIncludePaths(doc.Root)
	want := []string{"ci/a.yml", "/ci/b.yml", "ci/*.yml"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if got := LocalIncludePaths(mustParse(t, "job:\n  script: [x]\n").Root); got != nil {
		t.Errorf("no include: got %q", got)
	}
}

func TestIncludeGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{"ci/*.yml", []string{"ci/a.yml", "ci/.hidden.yml"}, []string{"ci/sub/a.yml", "ci/a.yaml", "xci/a.yml"}},
		{"ci/**.yml", []string{"ci/a.yml", "ci/sub/deep/a.yml"}, []string{"other/a.yml"}},
		{"ci/**/*.yml", []string{"ci/a.yml", "ci/sub/a.yml"}, []string{"cia.yml"}},
		{"**/*.yml", []string{"a.yml", "x/y/a.yml"}, []string{"a.yaml"}},
		{"ci/?.yml", []string{"ci/a.yml"}, []string{"ci/ab.yml", "ci//.yml"}},
		{"ci/{build,deploy}.yml", []string{"ci/build.yml", "ci/deploy.yml"}, []string{"ci/test.yml", "ci/{build,deploy}.yml"}},
		{"ci/a+b(1).yml*", []string{"ci/a+b(1).yml", "ci/a+b(1).yml.bak"}, []string{"ci/aab1.yml"}},
	} {
		re := IncludeGlob(tc.pattern)
		if re == nil {
			t.Fatalf("%s: not a wildcard", tc.pattern)
		}
		for _, p := range tc.match {
			if !re.MatchString(p) {
				t.Errorf("%s does not match %s", tc.pattern, p)
			}
		}
		for _, p := range tc.noMatch {
			if re.MatchString(p) {
				t.Errorf("%s matches %s", tc.pattern, p)
			}
		}
	}
	for _, p := range []string{"ci/build.yml", "ci/{unclosed.yml"} {
		if IncludeGlob(p) != nil {
			t.Errorf("IncludeGlob(%q) is not nil", p)
		}
	}
}

func TestIncludeGlobDir(t *testing.T) {
	for pattern, want := range map[string]string{
		"ci/*.yml":        "ci",
		"ci/sub/**.yml":   "ci/sub",
		"ci/x*/a.yml":     "ci",
		"*.yml":           "",
		"ci/{a,b}/c.yml":  "ci",
		"a/b/c?.yml":      "a/b",
		"ci/deploy/*.yml": "ci/deploy",
	} {
		if got := IncludeGlobDir(pattern); got != want {
			t.Errorf("IncludeGlobDir(%q) = %q, want %q", pattern, got, want)
		}
	}
}

func TestWithContext(t *testing.T) {
	root := mustParse(t, `workflow:
  rules:
    - if: $CI_COMMIT_BRANCH
variables:
  A: root
include: ci/x.yml
.tpl:
  image: alpine
build:
  script: [x]
`)
	included := mustParse(t, `variables:
  A: included
deploy:
  extends: .tpl
  script: [x]
`)
	before := len(included.MappingNode().Content)
	got := WithContext(included, []*Document{included, root})
	if len(included.MappingNode().Content) != before {
		t.Fatal("WithContext changed the document")
	}
	m := got.MappingNode()
	for _, key := range []string{"workflow", ".tpl"} {
		k, v := FindKeyNode(m, key)
		if v == nil {
			t.Errorf("%s not added", key)
			continue
		}
		if k.Line != ContextLine || v.Line != ContextLine {
			t.Errorf("%s added on line %d/%d, want ContextLine", key, k.Line, v.Line)
		}
	}
	for _, key := range []string{"include", "build"} {
		if FindKey(m, key) != nil {
			t.Errorf("%s added, want only global keywords and hidden jobs", key)
		}
	}
	if v := FindKey(FindKey(m, "variables"), "A"); v == nil || v.Value != "root" || v.Line != ContextLine {
		t.Errorf("the root's variable doesn't override the included one: %v", v)
	}

	if WithContext(root, []*Document{root}) != root {
		t.Error("nothing to add, but a new document")
	}
}

// A multi-line scalar copied into the context keeps no traced source lines;
// they would point into the other file.
func TestWithContext_NoTracedLines(t *testing.T) {
	root := mustParse(t, ".tpl:\n  script:\n    - echo one\n      echo two\n")
	job := mustParse(t, "job:\n  script: [x]\n")
	got := WithContext(job, []*Document{job, root})
	item := FindKey(FindKey(got.MappingNode(), ".tpl"), "script").Content[0]
	if line := ScalarContentLine(item, 0); line != ContextLine {
		t.Errorf("line = %d, want ContextLine", line)
	}
}

// A document or another file that isn't a mapping has nothing to add or to
// take; GitLab rejects such a file anyway.
func TestWithContext_NotAMapping(t *testing.T) {
	list := mustParse(t, "- a\n- b\n")
	root := mustParse(t, "workflow:\n  rules:\n    - when: always\n")
	if WithContext(list, []*Document{list, root}) != list {
		t.Error("a list document was given context")
	}
	job := mustParse(t, "job:\n  script: [x]\n")
	if WithContext(job, []*Document{list, job}) != job {
		t.Error("a list document gave context")
	}
}

// A node that expanded aliases share is copied once, so the copy stays as
// small as the original.
func TestWithContext_SharedNodesCopiedOnce(t *testing.T) {
	root := mustParse(t, ".base: &base\n  image: alpine\n.a:\n  <<: *base\n.b: *base\n")
	job := mustParse(t, "job:\n  script: [x]\n")
	got := WithContext(job, []*Document{job, root})
	m := got.MappingNode()
	a, b := FindKey(m, ".base"), FindKey(m, ".b")
	if a == nil || b == nil {
		t.Fatal("templates not added")
	}
	if a != b {
		t.Error("the node .base and .b share was copied twice")
	}
	if a == FindKey(root.MappingNode(), ".base") {
		t.Error("the original node was added instead of a copy")
	}
}

func TestMergeOrder(t *testing.T) {
	root, a, nested, b := &Document{File: "root"}, &Document{File: "a"}, &Document{File: "nested"}, &Document{File: "b"}
	order := func() string {
		var got []string
		for _, d := range MergeOrder(root) {
			got = append(got, d.File)
		}
		return strings.Join(got, " ")
	}
	root.Includes = []*Document{a, b}
	a.Includes = []*Document{nested}
	if got, want := order(), "nested a b root"; got != want {
		t.Errorf("nested: %s, want %s", got, want)
	}
	// Included again by b, nested overrides a after all.
	b.Includes = []*Document{nested}
	if got, want := order(), "a nested b root"; got != want {
		t.Errorf("included twice: %s, want %s", got, want)
	}
	nested.Includes = []*Document{a}
	if got := strings.Fields(order()); len(got) != 4 || got[3] != "root" {
		t.Errorf("cycle: %v", got)
	}
}

// The merge of mappings shared by aliases stays linear in the number of pairs.
func TestWithContext_SharedNodesMergedOnce(t *testing.T) {
	var src strings.Builder
	src.WriteString(".l0: &l0\n  x: 1\n")
	for i := 1; i < 40; i++ {
		fmt.Fprintf(&src, ".l%d: &l%d\n  a: *l%d\n  b: *l%d\n", i, i, i-1, i-1)
	}
	low, high := mustParse(t, src.String()), mustParse(t, src.String())
	WithContext(low, []*Document{low, high})
}

func TestWithContext_MergesLikeGitLab(t *testing.T) {
	first := mustParse(t, "variables:\n  A: first\n  B: first\n.tpl:\n  image: first\n  tags: [first]\njob:\n  image: first\n  script: [first]\nonly-here:\n  script: [x]\n")
	second := mustParse(t, "variables:\n  B: second\n.tpl:\n  image: second\njob:\n  image: second\n  variables:\n    V: second\n")
	root := mustParse(t, "include: [first.yml, second.yml]\nvariables:\n  C: root\njob:\n  script: [root]\n")
	pipeline := []*Document{first, second, root}

	m := WithContext(first, pipeline).MappingNode()
	variables := FindKey(m, "variables")
	for key, want := range map[string]string{"A": "first", "B": "second", "C": "root"} {
		if v := FindKey(variables, key); v == nil || v.Value != want {
			t.Errorf("variables.%s = %v, want %s", key, v, want)
		}
	}
	if FindKey(variables, "A").Line != 2 {
		t.Error("the file's own entry lost its line")
	}
	tpl := FindKey(m, ".tpl")
	if v := FindKey(tpl, "image"); v.Value != "second" || v.Line != ContextLine {
		t.Errorf(".tpl image = %v, want the second file's on ContextLine", v)
	}
	if v := FindKey(tpl, "tags"); v == nil || v.Line != 7-1 {
		t.Errorf(".tpl tags = %v, want the file's own", v)
	}
	jobKey, job := FindKeyNode(m, "job")
	if jobKey.Line != ContextLine || job.Line != ContextLine {
		t.Error("a job several files set belongs to the last of them")
	}
	if v := FindKey(job, "script"); v.Line != ContextLine || v.Content[0].Value != "root" {
		t.Errorf("script = %v, want the root's: lists are replaced", v)
	}
	if v := FindKey(FindKey(job, "variables"), "V"); v == nil || v.Value != "second" {
		t.Errorf("job variables.V = %v", v)
	}
	if FindKey(m, "only-here") == nil {
		t.Error("the file's own job is gone")
	}

	got := WithContext(root, pipeline).MappingNode()
	if FindKey(got, "only-here") != nil {
		t.Error("a job of another file was added")
	}
	if len(FindKey(root.MappingNode(), "job").Content) != 2 {
		t.Error("the document was changed")
	}
}
