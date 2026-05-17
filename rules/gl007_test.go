package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings007(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL007.Check(doc.Root, "test.yml")
}

func TestGL007_EntirelyVariable(t *testing.T) {
	f := findings007(t, `
build:
  image: $BUILD_IMAGE
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for fully-variable image, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
}

func TestGL007_BraceForm(t *testing.T) {
	f := findings007(t, `
build:
  image: ${BUILD_IMAGE}
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace-form variable image, got %d", len(f))
	}
}

func TestGL007_UserControlledTag(t *testing.T) {
	f := findings007(t, `
deploy:
  image: registry.example.com/app:$CI_COMMIT_REF_SLUG
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for user-controlled variable in tag, got %d", len(f))
	}
}

func TestGL007_UserControlledRefName(t *testing.T) {
	f := findings007(t, `
build:
  image: myrepo/app:$CI_COMMIT_REF_NAME
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_REF_NAME in image, got %d", len(f))
	}
}

func TestGL007_CommitTagInImage(t *testing.T) {
	f := findings007(t, `
build:
  image: registry.example.com/app:$CI_COMMIT_TAG
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_TAG in image tag, got %d", len(f))
	}
}

func TestGL007_SafeImage_NoFinding(t *testing.T) {
	f := findings007(t, `
build:
  image: node:20.11.0
  script: [npm ci]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for pinned image, got %d", len(f))
	}
}

func TestGL007_SafeDigest_NoFinding(t *testing.T) {
	f := findings007(t, `
build:
  image: node@sha256:abc123
  script: [npm ci]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for digest-pinned image, got %d", len(f))
	}
}

func TestGL007_SafeRegistryVar_NoFinding(t *testing.T) {
	// CI_REGISTRY_IMAGE is set by GitLab, not by external actors
	f := findings007(t, `
build:
  image: $CI_REGISTRY_IMAGE:1.2.3
  script: [make]
`)
	// Not entirely a variable, and CI_REGISTRY_IMAGE is not in userControlledImageVars
	if len(f) != 0 {
		t.Errorf("expected no finding for $CI_REGISTRY_IMAGE with pinned tag, got %d", len(f))
	}
}

func TestGL007_GlobalImage(t *testing.T) {
	f := findings007(t, `
image: $BUILD_IMAGE

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for global variable image, got %d", len(f))
	}
}

func TestGL007_DefaultImage(t *testing.T) {
	f := findings007(t, `
default:
  image: $BUILD_IMAGE

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in default: image, got %d", len(f))
	}
}

func TestGL007_ServiceVariable(t *testing.T) {
	f := findings007(t, `
build:
  image: node:20.11.0
  services:
    - $DB_IMAGE
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for variable in services, got %d", len(f))
	}
}

func TestGL007_LineNumber(t *testing.T) {
	f := findings007(t, `
build:
  image: $BUILD_IMAGE
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
