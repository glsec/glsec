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
