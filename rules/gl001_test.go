package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL001.Check(doc.Root, "test.yml")
}

func TestGL001_MutableTag(t *testing.T) {
	f := findings(t, `
build:
  image: node:latest
  script: [npm run build]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL001_NoTag(t *testing.T) {
	f := findings(t, `
build:
  image: alpine
  script: [echo hi]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL001_PinnedVersion(t *testing.T) {
	f := findings(t, `
build:
  image: node:20.11.0
  script: [npm run build]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings, got %v", f)
	}
}

func TestGL001_DigestPinned(t *testing.T) {
	f := findings(t, `
build:
  image: node@sha256:abc123def456
  script: [npm run build]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for digest-pinned image")
	}
}

func TestGL001_MappingForm(t *testing.T) {
	f := findings(t, `
build:
  image:
    name: node:latest
    entrypoint: [""]
  script: [npm run build]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mapping form, got %d", len(f))
	}
}

func TestGL001_Services(t *testing.T) {
	f := findings(t, `
build:
  image: node:20.11.0
  services:
    - docker:dind
    - name: postgres:latest
      alias: db
  script: [npm run build]
`)
	// docker:dind is a named variant tag, not in mutableTags; only postgres:latest triggers
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (postgres:latest), got %d", len(f))
	}
}

func TestGL001_DefaultBlock(t *testing.T) {
	f := findings(t, `
default:
  image: ubuntu:latest
  services:
    - docker:dind

build:
  script: [make]
`)
	// docker:dind is a named variant tag; only ubuntu:latest triggers
	if len(f) != 1 {
		t.Fatalf("expected 1 finding from default block (ubuntu:latest), got %d", len(f))
	}
}

func TestGL001_TopLevelImage(t *testing.T) {
	f := findings(t, `
image: ruby:latest

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for top-level image, got %d", len(f))
	}
}

func TestGL001_LineNumbers(t *testing.T) {
	f := findings(t, `
build:
  image: node:latest
  script: [npm run build]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL001_Registry(t *testing.T) {
	f := findings(t, `
build:
  image: registry.company.com:5000/node:20.11.0
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for pinned registry image, got %v", f)
	}
}

func TestGL001_RegistryLatest(t *testing.T) {
	f := findings(t, `
build:
  image: registry.company.com:5000/node:latest
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for registry image with latest tag, got %d", len(f))
	}
}
