package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings059(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL059.Check(doc.Root, "test.yml")
}

func TestGL059_TokenBuildArg(t *testing.T) {
	f := findings059(t, `
build:
  script:
    - docker build --build-arg NPM_TOKEN=$NPM_TOKEN -t myapp .
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL059" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL059_LiteralPassword(t *testing.T) {
	f := findings059(t, `
build:
  script:
    - docker build --build-arg PASSWORD=hunter2 .
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for PASSWORD literal, got %d", len(f))
	}
}

func TestGL059_BuildxAndEqualsForm(t *testing.T) {
	f := findings059(t, `
build:
  script:
    - docker buildx build --build-arg=API_KEY=$API_KEY -t myapp .
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for buildx + =form, got %d", len(f))
	}
}

func TestGL059_MultipleArgs(t *testing.T) {
	f := findings059(t, `
build:
  script:
    - docker build --build-arg VERSION=1.0 --build-arg AUTH_TOKEN=$AUTH_TOKEN -t myapp .
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (only AUTH_TOKEN, not VERSION), got %d", len(f))
	}
}

func TestGL059_GenericArgNotFlagged(t *testing.T) {
	f := findings059(t, `
build:
  script:
    - docker build --build-arg VERSION=1.0 --build-arg BYPASS_CACHE=true -t myapp .
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for VERSION/BYPASS_CACHE, got %d", len(f))
	}
}

func TestGL059_SecretMountNotFlagged(t *testing.T) {
	f := findings059(t, `
build:
  script:
    - docker build --secret id=npm_token,src=/tmp/npm_token -t myapp .
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for --secret mount, got %d", len(f))
	}
}

func TestGL059_CommentNotFlagged(t *testing.T) {
	f := findings059(t, `
build:
  script:
    - "# docker build --build-arg API_KEY=$API_KEY is unsafe"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}
