package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings076(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL076.Check(doc.Root, "test.yml")
}

func TestGL076_SeccompUnconfined(t *testing.T) {
	f := findings076(t, `
test:
  script:
    - docker run --security-opt seccomp=unconfined myimage ./run.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL076" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL076_ApparmorUnconfined(t *testing.T) {
	f := findings076(t, `
test:
  script:
    - docker run --security-opt apparmor=unconfined myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for apparmor=unconfined, got %d", len(f))
	}
}

func TestGL076_EqualsForm(t *testing.T) {
	f := findings076(t, `
test:
  script:
    - docker run --security-opt=seccomp=unconfined myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --security-opt=seccomp=unconfined, got %d", len(f))
	}
}

func TestGL076_NoNewPrivilegesNotFlagged(t *testing.T) {
	f := findings076(t, `
test:
  script:
    - docker run --security-opt no-new-privileges myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for no-new-privileges, got %d", len(f))
	}
}

func TestGL076_NoSecurityOpt(t *testing.T) {
	f := findings076(t, `
test:
  script:
    - docker run myimage ./run.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without --security-opt, got %d", len(f))
	}
}

func TestGL076_NoDockerRun(t *testing.T) {
	f := findings076(t, `
test:
  script:
    - echo "avoid --security-opt seccomp=unconfined"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without docker run, got %d", len(f))
	}
}

func TestGL076_CommentNotFlagged(t *testing.T) {
	f := findings076(t, `
test:
  script:
    - "# docker run --security-opt seccomp=unconfined is discouraged"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}
