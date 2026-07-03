package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings077(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL077.Check(doc.Root, "test.yml")
}

func TestGL077_IpcHost(t *testing.T) {
	f := findings077(t, `
test:
  script:
    - docker run --ipc host myimage ./run.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL077" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL077_IpcHostEqualsForm(t *testing.T) {
	f := findings077(t, `
test:
  script:
    - docker run --ipc=host myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --ipc=host, got %d", len(f))
	}
}

func TestGL077_IpcContainerNotFlagged(t *testing.T) {
	f := findings077(t, `
test:
  script:
    - docker run --ipc container:abc123 myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for --ipc container:, got %d", len(f))
	}
}

func TestGL077_NoIpcFlag(t *testing.T) {
	f := findings077(t, `
test:
  script:
    - docker run myimage ./run.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without --ipc, got %d", len(f))
	}
}

func TestGL077_NoDockerRun(t *testing.T) {
	f := findings077(t, `
test:
  script:
    - echo "use --ipc host for shared memory"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without docker run, got %d", len(f))
	}
}

func TestGL077_CommentNotFlagged(t *testing.T) {
	f := findings077(t, `
test:
  script:
    - "# docker run --ipc host is discouraged"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}
