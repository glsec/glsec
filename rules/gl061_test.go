package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings061(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL061.Check(doc.Root, "test.yml")
}

func TestGL061_PidHost(t *testing.T) {
	f := findings061(t, `
test:
  script:
    - docker run --pid host myimage ./perf-test.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL061" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL061_PidHostEqualsForm(t *testing.T) {
	f := findings061(t, `
test:
  script:
    - docker run --pid=host myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --pid=host, got %d", len(f))
	}
}

func TestGL061_PidContainerNotFlagged(t *testing.T) {
	f := findings061(t, `
test:
  script:
    - docker run --pid container:abc123 myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for --pid container:, got %d", len(f))
	}
}

func TestGL061_NoPidFlag(t *testing.T) {
	f := findings061(t, `
test:
  script:
    - docker run myimage ./perf-test.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without --pid, got %d", len(f))
	}
}

func TestGL061_NoDockerRun(t *testing.T) {
	f := findings061(t, `
test:
  script:
    - echo "use --pid host for profiling"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without docker run, got %d", len(f))
	}
}

func TestGL061_CommentNotFlagged(t *testing.T) {
	f := findings061(t, `
test:
  script:
    - "# docker run --pid host is discouraged"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}
