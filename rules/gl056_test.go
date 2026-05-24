package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings056(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL056.Check(doc.Root, "test.yml")
}

func TestGL056_PrivilegedFlag(t *testing.T) {
	f := findings056(t, `
test:
  script:
    - docker run --privileged myimage ./run-tests.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL056" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
	if f[0].Job != "test" {
		t.Errorf("expected job test, got %q", f[0].Job)
	}
}

func TestGL056_PrivilegedTrue(t *testing.T) {
	f := findings056(t, `
test:
  script:
    - docker run --privileged=true myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --privileged=true, got %d", len(f))
	}
}

func TestGL056_ContainerRunSubcommand(t *testing.T) {
	f := findings056(t, `
test:
  script:
    - docker container run --privileged myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 'docker container run', got %d", len(f))
	}
}

func TestGL056_BeforeScript(t *testing.T) {
	f := findings056(t, `
test:
  before_script:
    - docker run --privileged setup
  script:
    - true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL056_PrivilegedDisabledNotFlagged(t *testing.T) {
	f := findings056(t, `
test:
  script:
    - docker run --privileged=false myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for --privileged=false, got %d", len(f))
	}
}

func TestGL056_CapAddNotFlagged(t *testing.T) {
	f := findings056(t, `
test:
  script:
    - docker run --cap-add NET_ADMIN myimage ./run-tests.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for --cap-add, got %d", len(f))
	}
}

func TestGL056_CommentNotFlagged(t *testing.T) {
	f := findings056(t, `
test:
  script:
    - "# docker run --privileged is not allowed here"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}

func TestGL056_PlainDockerRunNotFlagged(t *testing.T) {
	f := findings056(t, `
test:
  script:
    - docker run myimage ./run-tests.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for plain docker run, got %d", len(f))
	}
}
