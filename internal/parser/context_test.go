// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
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
	got := WithContext(included, []*Document{root})
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
	if v := FindKey(FindKey(m, "variables"), "A"); v == nil || v.Value != "included" {
		t.Errorf("the document's own variables: were replaced: %v", v)
	}

	if WithContext(root, nil) != root {
		t.Error("nothing to add, but a new document")
	}
}

// A multi-line scalar copied into the context keeps no traced source lines;
// they would point into the other file.
func TestWithContext_NoTracedLines(t *testing.T) {
	root := mustParse(t, ".tpl:\n  script:\n    - echo one\n      echo two\n")
	got := WithContext(mustParse(t, "job:\n  script: [x]\n"), []*Document{root})
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
	if WithContext(list, []*Document{root}) != list {
		t.Error("a list document was given context")
	}
	job := mustParse(t, "job:\n  script: [x]\n")
	if WithContext(job, []*Document{list}) != job {
		t.Error("a list document gave context")
	}
}

// A node that expanded aliases share is copied once, so the copy stays as
// small as the original.
func TestWithContext_SharedNodesCopiedOnce(t *testing.T) {
	root := mustParse(t, ".base: &base\n  image: alpine\n.a:\n  <<: *base\n.b: *base\n")
	got := WithContext(mustParse(t, "job:\n  script: [x]\n"), []*Document{root})
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
