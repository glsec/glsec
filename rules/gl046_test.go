// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings046(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL046.Check(doc.Root, "test.yml")
}

func TestGL046_RefNameAsKey(t *testing.T) {
	f := findings046(t, `
build:
  cache:
    key: $CI_COMMIT_REF_NAME
    paths:
      - node_modules/
  script: [npm ci]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL046_RefSlugAsKey(t *testing.T) {
	f := findings046(t, `
build:
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths: [.cache/]
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_REF_SLUG, got %d", len(f))
	}
}

func TestGL046_BranchAsKey(t *testing.T) {
	f := findings046(t, `
build:
  cache:
    key: "$CI_COMMIT_BRANCH-node"
    paths: [node_modules/]
  script: [npm ci]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_BRANCH, got %d", len(f))
	}
}

func TestGL046_UserControlledPrefix(t *testing.T) {
	f := findings046(t, `
build:
  cache:
    key:
      files:
        - package-lock.json
      prefix: $CI_COMMIT_REF_NAME
    paths: [node_modules/]
  script: [npm ci]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for user-controlled prefix, got %d", len(f))
	}
}

func TestGL046_FilesOnlyKeyNoFinding(t *testing.T) {
	f := findings046(t, `
build:
  cache:
    key:
      files:
        - package-lock.json
    paths: [node_modules/]
  script: [npm ci]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for files-only key, got %d", len(f))
	}
}

func TestGL046_StaticKeyNoFinding(t *testing.T) {
	f := findings046(t, `
build:
  cache:
    key: "node-modules-v1"
    paths: [node_modules/]
  script: [npm ci]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for static key, got %d", len(f))
	}
}

func TestGL046_DefaultBlockFlagged(t *testing.T) {
	f := findings046(t, `
default:
  cache:
    key: $CI_COMMIT_REF_NAME
    paths: [.cache/]

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in default: cache:, got %d", len(f))
	}
}

func TestGL046_MultipleCachesOneUserControlled(t *testing.T) {
	f := findings046(t, `
build:
  cache:
    - key: $CI_COMMIT_REF_NAME
      paths: [node_modules/]
    - key: "static-key"
      paths: [.cache/]
  script: [npm ci]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (only the user-controlled key), got %d", len(f))
	}
}

func TestGL046_MRSourceBranchAsKey(t *testing.T) {
	f := findings046(t, `
build:
  cache:
    key: $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
    paths: [node_modules/]
  script: [npm ci]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for MR source branch variable, got %d", len(f))
	}
}

func TestGL046_NoCacheNoFinding(t *testing.T) {
	f := findings046(t, `
build:
  script: [npm ci, npm run build]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without cache block, got %d", len(f))
	}
}

func TestGL046_JobNameInFinding(t *testing.T) {
	f := findings046(t, `
my-build-job:
  cache:
    key: $CI_COMMIT_REF_NAME
    paths: [node_modules/]
  script: [npm ci]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Job != "my-build-job" {
		t.Errorf("expected job name 'my-build-job', got %q", f[0].Job)
	}
}

func TestGL046_Unprotect(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []finding.Severity
	}{
		{"default policy writes", `
build:
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [make]
`, []finding.Severity{finding.Warn}},
		{"push policy", `
warm:
  cache:
    key: deps
    unprotect: true
    policy: push
    paths: [vendor/]
  script: [make]
`, []finding.Severity{finding.Warn}},
		{"variable policy", `
build:
  cache:
    key: deps
    unprotect: true
    policy: $CACHE_POLICY
    paths: [vendor/]
  script: [make]
`, []finding.Severity{finding.Warn}},
		{"pull policy only reads", `
test:
  cache:
    key: deps
    unprotect: true
    policy: pull
    paths: [vendor/]
  script: [make]
`, nil},
		{"unprotect false", `
build:
  cache:
    key: deps
    unprotect: false
    paths: [vendor/]
  script: [make]
`, nil},
		{"deploy job is error", `
deploy:
  environment: production
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [./deploy.sh]
`, []finding.Severity{finding.Error}},
		{"merge request job is error", `
build:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [make]
`, []finding.Severity{finding.Error}},
		{"cache list flags only the writing entry", `
build:
  cache:
    - key: gems
      unprotect: true
      policy: pull
      paths: [vendor/]
    - key: node
      unprotect: true
      paths: [node_modules/]
  script: [make]
`, []finding.Severity{finding.Warn}},
		{"alias to an anchored cache", `
.deps-cache: &deps-cache
  key: deps
  unprotect: true
  paths: [vendor/]
build:
  cache:
    - *deps-cache
  script: [make]
`, []finding.Severity{finding.Warn}},
		{"merge key pulls in unprotect", `
.base-cache: &base-cache
  key: deps
  paths: [vendor/]
.unprotected: &unprotected
  <<: *base-cache
  unprotect: true
build:
  cache: *unprotected
  script: [make]
`, []finding.Severity{finding.Warn}},
		{"merge key pulls in policy pull", `
.pull-cache: &pull-cache
  key: deps
  policy: pull
  paths: [vendor/]
test:
  cache:
    <<: *pull-cache
    unprotect: true
  script: [make]
`, nil},
		{"default-branch-only writer", `
warm-cache:
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
      when: never
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [make]
`, nil},
		{"protected-ref-only writer", `
warm-cache:
  rules:
    - if: $CI_COMMIT_REF_PROTECTED == "true"
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [make]
`, nil},
		{"literal master branch", `
warm-cache:
  rules:
    - if: $CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "master"
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [make]
`, nil},
		{"only main", `
warm-cache:
  only: [main]
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [make]
`, nil},
		{"default branch or merge request still writes from MRs", `
build:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH || $CI_PIPELINE_SOURCE == "merge_request_event"
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [make]
`, []finding.Severity{finding.Error}},
		{"non-default branches", `
build:
  rules:
    - if: $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
  script: [make]
`, []finding.Severity{finding.Warn}},
		{"anchor shared by several jobs is reported per job at the anchor", `
.deps-cache: &deps-cache
  key: deps
  unprotect: true
  paths: [vendor/]
build:
  cache: *deps-cache
  script: [make]
deploy:
  environment: production
  cache: *deps-cache
  script: [./deploy.sh]
`, []finding.Severity{finding.Warn, finding.Error}},
		{"hidden template job", `
.cache-push:
  cache:
    key: deps
    unprotect: true
    policy: push
    paths: [vendor/]
`, nil},
		{"default section", `
default:
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
build:
  script: [make]
`, []finding.Severity{finding.Warn}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := findings046(t, tc.yaml)
			if len(f) != len(tc.want) {
				t.Fatalf("got %d findings, want %d", len(f), len(tc.want))
			}
			for i, sev := range tc.want {
				if f[i].Severity != sev {
					t.Errorf("finding %d severity = %s, want %s", i, f[i].Severity, sev)
				}
			}
		})
	}
}

// A protected-only job's cache is kept apart from unprotected refs unless it
// sets unprotect: true (#1003).
func TestGL046_ProtectedOnlyKey(t *testing.T) {
	for _, tc := range []struct {
		cache string
		want  int
	}{
		{"    key: \"$CI_COMMIT_REF_NAME\"\n    paths: [.cache/]\n", 0},
		{"    key: \"$CI_COMMIT_REF_NAME\"\n    unprotect: true\n    paths: [.cache/]\n", 1},
	} {
		doc, err := parser.Parse([]byte("build:\n  rules:\n    - if: $CI_COMMIT_REF_PROTECTED == \"true\"\n  cache:\n"+tc.cache+"  script: [make]\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL046.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%q: got %d findings, want %d", tc.cache, got, tc.want)
		}
	}
	// A job that runs on any ref is still reported.
	doc, err := parser.Parse([]byte("build:\n  cache:\n    key: \"$CI_COMMIT_REF_NAME\"\n    paths: [.cache/]\n  script: [make]\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(GL046.Check(doc.Root, "test.yml")); got != 1 {
		t.Errorf("unrestricted job: got %d findings, want 1", got)
	}
}
