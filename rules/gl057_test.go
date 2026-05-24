package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings057(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL057.Check(doc.Root, "test.yml")
}

func TestGL057_CapAddAllIsError(t *testing.T) {
	f := findings057(t, `
test:
  script:
    - docker run --cap-add ALL myimage ./test.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error || f[0].RuleID != "GL057" {
		t.Errorf("expected error severity for --cap-add ALL, got %+v", f[0])
	}
}

func TestGL057_SysAdminIsWarn(t *testing.T) {
	f := findings057(t, `
test:
  script:
    - docker run --cap-add SYS_ADMIN myimage ./mount-test.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected warn severity for SYS_ADMIN, got %q", f[0].Severity)
	}
}

func TestGL057_EqualsAndCapPrefix(t *testing.T) {
	f := findings057(t, `
test:
  script:
    - docker run --cap-add=CAP_SYS_PTRACE myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --cap-add=CAP_SYS_PTRACE, got %d", len(f))
	}
}

func TestGL057_MultipleCapsOneLine(t *testing.T) {
	f := findings057(t, `
test:
  script:
    - docker run --cap-add ALL --cap-add NET_ADMIN myimage
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL057_SafeCapNotFlagged(t *testing.T) {
	f := findings057(t, `
test:
  script:
    - docker run --cap-add NET_BIND_SERVICE myimage ./server-test.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for NET_BIND_SERVICE, got %d", len(f))
	}
}

func TestGL057_NoDockerRun(t *testing.T) {
	f := findings057(t, `
test:
  script:
    - echo "--cap-add SYS_ADMIN documented in our README"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without docker run, got %d", len(f))
	}
}

func TestGL057_CommentNotFlagged(t *testing.T) {
	f := findings057(t, `
test:
  script:
    - "# docker run --cap-add ALL would be dangerous"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}
