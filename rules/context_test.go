// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
)

// A child pipeline or included file is checked in the context that brings it
// into a pipeline (#1502).
func TestPipelineContext(t *testing.T) {
	prodChild := `
deploy-prod:
  environment: production
  rules:
    - if: $CI_PIPELINE_SOURCE == "parent_pipeline"
  script:
    - ./deploy.sh
push:
  rules:
    - if: $CI_PIPELINE_SOURCE == "parent_pipeline"
  script:
    - docker push "$CI_REGISTRY_IMAGE:latest"
federate:
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: $CI_PIPELINE_SOURCE == "parent_pipeline"
  script:
    - aws sts get-caller-identity
`
	unguarded := `
deploy:
  environment: production
  script:
    - ./deploy.sh
federate:
  id_tokens:
    AWS_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - aws sts get-caller-identity
`
	for _, tc := range []struct {
		name string
		r    rule.Rule
		src  string
		set  func(d *parser.Document)
		want int
	}{
		{"GL013 open child", GL013, prodChild, func(d *parser.Document) { d.Child = true }, 1},
		{"GL013 same file on its own", GL013, prodChild, func(*parser.Document) {}, 0},
		{"GL080 open child", GL080, prodChild, func(d *parser.Document) { d.Child = true }, 1},
		{"GL081 open child", GL081, prodChild, func(d *parser.Document) { d.Child = true }, 1},
		{"GL013 protected child", GL013, unguarded, func(d *parser.Document) { d.Child, d.ProtectedByParent = true, true }, 0},
		{"GL081 protected child", GL081, unguarded, func(d *parser.Document) { d.Child, d.ProtectedByParent = true, true }, 0},
		{"GL080 file included by a protected child", GL080, "publish:\n  script:\n    - docker push \"$CI_REGISTRY_IMAGE:latest\"\n", func(d *parser.Document) {
			d.IncludedBy = &parser.Document{Child: true, ProtectedByParent: true}
		}, 0},
		{"GL080 unprotected include", GL080, "publish:\n  script:\n    - docker push \"$CI_REGISTRY_IMAGE:latest\"\n", func(*parser.Document) {}, 1},
		{"GL053 child", GL053, "build:\n  script: [make]\n", func(d *parser.Document) { d.Child = true }, 0},
		{"GL053 file a child includes", GL053, "build:\n  script: [make]\n", func(d *parser.Document) { d.IncludedBy = &parser.Document{Child: true} }, 0},
		{"GL053 root", GL053, "build:\n  script: [make]\n", func(*parser.Document) {}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.src), "ci/child.yml")
			if err != nil {
				t.Fatal(err)
			}
			tc.set(doc)
			if got := Check(tc.r, doc, "ci/child.yml"); len(got) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(got), got)
			}
		})
	}
}

// GL080 leaves a production deploy's open entry to GL013 (#1490), and names
// an entry with no condition at all.
func TestGL080_EntryLabels(t *testing.T) {
	if f := findings080(t, "deploy:\n  environment: production\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: manual\n  script:\n    - ./deploy.sh\n"); len(f) != 0 {
		t.Fatalf("GL013 owns the production deploy's open entry, got %v", f)
	}
	f := findings080(t, "push:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - allow_failure: true\n  script:\n    - docker push \"$CI_REGISTRY_IMAGE:latest\"\n")
	if len(f) != 1 || !strings.Contains(f[0].Message, "without if: (no condition)") {
		t.Fatalf("expected the no-condition label, got %v", f)
	}
}

func TestRunsOnProtectedRefsOnly(t *testing.T) {
	doc := parseDoc(t, "workflow:\n  rules:\n    - if: $CI_COMMIT_TAG\njob:\n  script: [make]\n")
	if !RunsOnProtectedRefsOnly(doc, parser.FindKey(parser.Unwrap(doc), "job")) {
		t.Fatal("a tags-only workflow keeps every job on protected refs")
	}
	doc = parseDoc(t, "job:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n  script: [make]\n")
	if RunsOnProtectedRefsOnly(doc, parser.FindKey(parser.Unwrap(doc), "job")) {
		t.Fatal("any branch is not protected")
	}
	if IncludeRulesProtectedOnly(nil) {
		t.Fatal("no rules is not protected")
	}
	doc = parseDoc(t, "rules:\n  - $CI_COMMIT_TAG\n")
	if IncludeRulesProtectedOnly(parser.FindKey(parser.Unwrap(doc), "rules")) {
		t.Fatal("an entry glsec can't read is not protected")
	}
}
