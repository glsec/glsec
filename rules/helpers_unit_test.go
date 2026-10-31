// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// Unit tests for the helpers that resolve inheritance, walk a pipeline's
// blocks and place findings (#1079).

func parseDoc(t *testing.T, src string) *yaml.Node {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc.Root
}

// jobNode returns the top-level value named name.
func jobNode(t *testing.T, doc *yaml.Node, name string) *yaml.Node {
	t.Helper()
	n := parser.FindKey(parser.Unwrap(doc), name)
	if n == nil {
		t.Fatalf("no job %q", name)
	}
	return n
}

// scriptItem returns the i-th item of job's script:.
func scriptItem(t *testing.T, doc *yaml.Node, job string, i int) *yaml.Node {
	t.Helper()
	return parser.FindKey(jobNode(t, doc, job), "script").Content[i]
}

func TestScriptMatchPos(t *testing.T) {
	doc := parseDoc(t, `job:
  script:
    - curl -fsSL https://x | sh
    - |
      make
      curl -fsSL https://x | sh
    - >
      make
      all
    - "make \
      all"
`)
	for _, tc := range []struct {
		name      string
		item      int
		match     string // the substring whose start is reported
		line, col int
	}{
		{"plain scalar", 0, "| sh", 3, 7},
		{"literal block, first line", 1, "make", 5, 0},
		{"literal block, later line", 1, "curl", 6, 0},
		{"folded block", 2, "all", 9, 0},
		{"double-quoted continuation, first line", 3, "make", 10, 7},
	} {
		item := scriptItem(t, doc, "job", tc.item)
		off := strings.Index(item.Value, tc.match)
		if off < 0 {
			t.Fatalf("%s: %q not in %q", tc.name, tc.match, item.Value)
		}
		if line, col := scriptMatchPos(item, off); line != tc.line || col != tc.col {
			t.Errorf("%s: scriptMatchPos = %d:%d, want %d:%d", tc.name, line, col, tc.line, tc.col)
		}
	}
	block := scriptItem(t, doc, "job", 1)
	for i, want := range []int{5, 6} {
		if line, col := scriptLinePos(block, i); line != want || col != 0 {
			t.Errorf("scriptLinePos(block, %d) = %d:%d, want %d:0", i, line, col, want)
		}
	}
	if line, col := scriptLinePos(scriptItem(t, doc, "job", 0), 0); line != 3 || col != 7 {
		t.Errorf("scriptLinePos(plain, 0) = %d:%d, want 3:7", line, col)
	}
}

func TestInheritance_Key(t *testing.T) {
	doc := parseDoc(t, `default:
  image: alpine:3.20
  tags: [docker]
before_script:
  - echo top
.base:
  image: node:22
  variables: {A: "1"}
.other:
  image: python:3.13
own:
  image: golang:1.27
  script: [x]
single:
  extends: .base
  script: [x]
list:
  extends: [.base, .other]
  script: [x]
plain:
  script: [x]
no-default:
  inherit:
    default: false
  script: [x]
some-default:
  inherit:
    default: [tags]
  script: [x]
missing:
  extends: .nowhere
  script: [x]
`)
	in := NewInheritance(doc)
	value := func(job, key string) string {
		v := in.Key(jobNode(t, doc, job), key)
		switch {
		case v == nil:
			return "<nil>"
		case v.Kind == yaml.ScalarNode:
			return v.Value
		case v.Kind == yaml.SequenceNode && len(v.Content) > 0:
			return v.Content[0].Value
		}
		return fmt.Sprint(v.Kind)
	}
	for _, tc := range []struct{ job, key, want string }{
		{"own", "image", "golang:1.27"},
		{"single", "image", "node:22"},
		{"list", "image", "python:3.13"}, // the later extends: entry wins
		{"plain", "image", "alpine:3.20"},
		{"plain", "tags", "docker"},
		{"plain", "before_script", "echo top"},
		{"no-default", "image", "<nil>"},
		{"no-default", "before_script", "<nil>"},
		{"some-default", "tags", "docker"},
		{"some-default", "image", "<nil>"},
		{"missing", "image", "alpine:3.20"},
		{"plain", "services", "<nil>"},
	} {
		if got := value(tc.job, tc.key); got != tc.want {
			t.Errorf("Key(%s, %s) = %s, want %s", tc.job, tc.key, got, tc.want)
		}
	}
}

func TestInheritance_ExtendsDepthAndCycles(t *testing.T) {
	var b strings.Builder
	b.WriteString(".l0:\n  image: deep:1\n")
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&b, ".l%d:\n  extends: .l%d\n", i, i-1)
	}
	b.WriteString("at-limit:\n  extends: .l10\n  script: [x]\npast-limit:\n  extends: .l11\n  script: [x]\n")
	b.WriteString(".a:\n  extends: .b\n.b:\n  extends: .a\ncycle:\n  extends: .a\n  script: [x]\n")
	doc := parseDoc(t, b.String())
	in := NewInheritance(doc)
	if v := in.Key(jobNode(t, doc, "at-limit"), "image"); v == nil || v.Value != "deep:1" {
		t.Errorf("11 levels: got %v, want deep:1", v)
	}
	if v := in.Key(jobNode(t, doc, "past-limit"), "image"); v != nil {
		t.Errorf("12 levels: got %q, want nothing past GitLab's limit", v.Value)
	}
	cycle := jobNode(t, doc, "cycle")
	if v := in.Key(cycle, "image"); v != nil {
		t.Errorf("cycle: got %q", v.Value)
	}
	if in.Has(cycle, "image") || len(in.Chain(cycle, "image")) != 0 {
		t.Error("cycle: Has or Chain found a key that isn't there")
	}
	if got := in.Effective(cycle); got == nil {
		t.Error("cycle: Effective returned nil")
	}
}

func TestInheritance_HasChainEffective(t *testing.T) {
	doc := parseDoc(t, `.base:
  artifacts:
    paths: [a]
    expire_in: 1 day
  image: node:22
.mid:
  extends: .base
  artifacts:
    paths: [b]
job:
  extends: [.mid]
  artifacts:
    name: x
  script: [x]
alone:
  script: [x]
`)
	in := NewInheritance(doc)
	job := jobNode(t, doc, "job")
	if !in.Has(job, "image") || in.Has(job, "services") || in.Has(jobNode(t, doc, "alone"), "image") {
		t.Error("Has: wrong answer")
	}
	var names []string
	for _, v := range in.Chain(job, "artifacts") {
		var keys []string
		for i := 0; i+1 < len(v.Content); i += 2 {
			keys = append(keys, v.Content[i].Value)
		}
		names = append(names, strings.Join(keys, ","))
	}
	if want := []string{"name", "paths", "paths,expire_in"}; !reflect.DeepEqual(names, want) {
		t.Errorf("Chain = %q, want %q (own first)", names, want)
	}
	eff := in.Effective(job)
	art := parser.FindKey(eff, "artifacts")
	got := map[string]string{}
	for i := 0; i+1 < len(art.Content); i += 2 {
		v := art.Content[i+1]
		if v.Kind == yaml.SequenceNode {
			got[art.Content[i].Value] = v.Content[0].Value
		} else {
			got[art.Content[i].Value] = v.Value
		}
	}
	if want := map[string]string{"name": "x", "paths": "b", "expire_in": "1 day"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Effective artifacts = %v, want %v (mappings merged, lists replaced)", got, want)
	}
	if v := parser.FindKey(eff, "image"); v == nil || v.Value != "node:22" {
		t.Error("Effective lost a key from the base")
	}
	if parser.FindKey(job, "image") != nil {
		t.Error("Effective changed the job node")
	}
	alone := jobNode(t, doc, "alone")
	if in.Effective(alone) != alone {
		t.Error("Effective of a job without extends: is not the job itself")
	}
}

func TestMergeMappings(t *testing.T) {
	base := parseDoc(t, "a: 1\nb:\n  x: 1\n  y: 1\nc: [1]\n")
	over := parseDoc(t, "b:\n  y: 2\n  z: 2\nc: [2]\nd: 2\n")
	got := mergeMappings(parser.Unwrap(base), parser.Unwrap(over))
	var out map[string]any
	if err := got.Decode(&out); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"a": 1, "b": map[string]any{"x": 1, "y": 2, "z": 2}, "c": []any{2}, "d": 2}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("mergeMappings = %v, want %v", out, want)
	}
	var baseOut map[string]any
	if err := parser.Unwrap(base).Decode(&baseOut); err != nil || baseOut["d"] != nil {
		t.Errorf("mergeMappings changed base: %v", baseOut)
	}
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Value: "s"}
	if mergeMappings(nil, scalar) != scalar || mergeMappings(parser.Unwrap(base), scalar) != scalar {
		t.Error("a non-mapping override should win as is")
	}
}

func TestInheritance_ExtendsResolvedAndIncludedOverride(t *testing.T) {
	doc := parseDoc(t, `include:
  - local: other.yml
.local:
  script: [x]
own:
  extends: .local
remote:
  extends: .from-other-file
override:
  rules:
    - when: manual
full:
  script: [x]
`)
	in := NewInheritance(doc)
	for _, tc := range []struct {
		job      string
		resolved bool
		override bool
	}{
		{"own", true, false},
		{"remote", false, true},
		{"override", true, true},
		{"full", true, false},
	} {
		job := jobNode(t, doc, tc.job)
		if got := in.ExtendsResolved(job); got != tc.resolved {
			t.Errorf("ExtendsResolved(%s) = %v, want %v", tc.job, got, tc.resolved)
		}
		if got := in.IncludedOverride(job); got != tc.override {
			t.Errorf("IncludedOverride(%s) = %v, want %v", tc.job, got, tc.override)
		}
	}
	noInclude := parseDoc(t, "override:\n  rules: [{when: manual}]\n")
	if NewInheritance(noInclude).IncludedOverride(jobNode(t, noInclude, "override")) {
		t.Error("IncludedOverride without include:")
	}
}

func TestInheritance_RunsOnWindows(t *testing.T) {
	doc := parseDoc(t, `default:
  tags: [saas-windows-medium-amd64]
win:
  script: [x]
.linux:
  tags: [docker, linux]
linux:
  extends: .linux
  script: [x]
windowsish:
  tags: [nowindowsfoo, darwin]
  script: [x]
scalar-tags:
  tags: windows
  script: [x]
`)
	in := NewInheritance(doc)
	for job, want := range map[string]bool{"win": true, "linux": false, "windowsish": false, "scalar-tags": false} {
		if got := in.RunsOnWindows(jobNode(t, doc, job)); got != want {
			t.Errorf("RunsOnWindows(%s) = %v, want %v", job, got, want)
		}
	}
}

func TestIsDeployLikeJob(t *testing.T) {
	doc := parseDoc(t, `env:
  environment: production
  script: [x]
env-prepare:
  environment: {name: production, action: prepare}
  stage: test
  script: [x]
by-name:
  script: [x]
by-stage:
  stage: release
  script: [x]
check:
  stage: deploy-check
  script: [x]
build:
  stage: build
  script: [x]
`)
	for job, want := range map[string]bool{
		"env": true, "env-prepare": false, "by-name": false, "by-stage": true, "check": false, "build": false,
	} {
		if got := IsDeployLikeJob(job, jobNode(t, doc, job)); got != want {
			t.Errorf("IsDeployLikeJob(%s) = %v, want %v", job, got, want)
		}
	}
	if !IsDeployLikeJob("publish-npm", jobNode(t, doc, "build")) {
		t.Error("a publish job name counts")
	}
}

func TestIsScriptListAndHookScript(t *testing.T) {
	doc := parseDoc(t, `job:
  script: [a, b]
  before_script: !reference [.x, before_script]
  after_script: one-line
  hooks:
    pre_get_sources_script: [git config x]
`)
	job := jobNode(t, doc, "job")
	// The parser turns a one-line string into a one-item list, as GitLab reads it.
	for key, want := range map[string]bool{"script": true, "before_script": false, "after_script": true, "nope": false} {
		if got := isScriptList(parser.FindKey(job, key)); got != want {
			t.Errorf("isScriptList(%s) = %v, want %v", key, got, want)
		}
	}
	if h := hookScriptNode(job); h == nil || len(h.Content) != 1 || h.Content[0].Value != "git config x" {
		t.Errorf("hookScriptNode = %v", h)
	}
	if hookScriptNode(parseDoc(t, "a: 1\n")) != nil {
		t.Error("hookScriptNode without hooks:")
	}
}

func TestEachScriptLine(t *testing.T) {
	doc := parseDoc(t, `before_script: [top-before]
after_script: [top-after]
default:
  before_script: [default-before]
  hooks:
    pre_get_sources_script: [default-hook]
.shared: &shared
  - shared
a:
  script: *shared
  after_script: [a-after]
b:
  script: *shared
  run:
    - name: step
      script: b-step
`)
	collect := func(each func(*yaml.Node, string, func(*yaml.Node, string, string))) []string {
		var got []string
		each(doc, "test.yml", func(line *yaml.Node, file, job string) {
			got = append(got, job+":"+line.Value)
		})
		sort.Strings(got)
		return got
	}
	once := collect(EachScriptLine)
	perJob := collect(EachScriptLinePerJob)
	wantOnce := []string{":default-before", ":default-hook", ":top-after", ":top-before", "a:a-after", "a:shared", "b:b-step"}
	if !reflect.DeepEqual(once, wantOnce) {
		t.Errorf("EachScriptLine = %q, want %q (an anchored block once)", once, wantOnce)
	}
	wantPerJob := append(append([]string{}, wantOnce...), "b:shared")
	sort.Strings(wantPerJob)
	if !reflect.DeepEqual(perJob, wantPerJob) {
		t.Errorf("EachScriptLinePerJob = %q, want %q (an anchored block per job)", perJob, wantPerJob)
	}
}

func TestEachVariablesBlock(t *testing.T) {
	doc := parseDoc(t, `variables: {TOP: "1"}
default:
  variables: {DEF: "1"}
workflow:
  rules:
    - if: $CI_COMMIT_TAG
      variables: {WF: "1"}
    - when: always
job:
  variables: {JOB: "1"}
  rules:
    - if: $X
      variables: {RULE: "1"}
    - not-a-mapping
  script: [x]
bare:
  script: [x]
`)
	var got []string
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, rule *yaml.Node) {
		if vars == nil {
			got = append(got, job+":<none>")
			return
		}
		got = append(got, fmt.Sprintf("%s:%s:%v", job, vars.Content[0].Value, rule != nil))
	})
	want := []string{":TOP:false", ":DEF:false", ":WF:true", "job:JOB:false", "job:RULE:true", "bare:<none>"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("eachVariablesBlock = %q, want %q", got, want)
	}
}
