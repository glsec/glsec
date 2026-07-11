package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings079(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL079.Check(doc.Root, "test.yml")
}

func TestGL079_ExtraIndexURL(t *testing.T) {
	f := findings079(t, `
build:
  script:
    - pip install foo --extra-index-url https://pypi.org/simple
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL079_ExtraIndexURLEquals(t *testing.T) {
	f := findings079(t, `
build:
  script:
    - pip3 install foo --extra-index-url=https://pypi.org/simple
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --extra-index-url=, got %d", len(f))
	}
}

func TestGL079_PythonMPip(t *testing.T) {
	f := findings079(t, `
build:
  script:
    - python -m pip install foo --extra-index-url https://pypi.org/simple
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for python -m pip, got %d", len(f))
	}
}

func TestGL079_BeforeScript(t *testing.T) {
	f := findings079(t, `
build:
  before_script:
    - pip install foo --extra-index-url https://pypi.org/simple
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL079_SingleIndexURL_NoFinding(t *testing.T) {
	f := findings079(t, `
build:
  script:
    - pip install --index-url https://pypi.internal.example.com/simple -r requirements.txt
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a single --index-url, got %d", len(f))
	}
}

func TestGL079_PlainInstall_NoFinding(t *testing.T) {
	f := findings079(t, `
build:
  script:
    - pip install foo -r requirements.txt
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a plain pip install, got %d", len(f))
	}
}

func TestGL079_CommentedLine_NoFinding(t *testing.T) {
	f := findings079(t, `
build:
  script:
    - "# pip install foo --extra-index-url https://pypi.org/simple"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a commented line, got %d", len(f))
	}
}

func TestGL079_NotPip_NoFinding(t *testing.T) {
	f := findings079(t, `
build:
  script:
    - echo "docs mention --extra-index-url as a flag"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when there is no pip install, got %d", len(f))
	}
}
