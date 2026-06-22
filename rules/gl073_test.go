package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings073rule(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL073.Check(doc.Root, "test.yml")
}

func TestGL073_PublicTrue(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    public: true
    paths:
      - build/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for public: true, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "public: true") {
		t.Errorf("expected public:true in message, got %q", f[0].Message)
	}
}

func TestGL073_AccessAll(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    access: all
    paths:
      - dist/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for access: all, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "access: all") {
		t.Errorf("expected access:all in message, got %q", f[0].Message)
	}
}

func TestGL073_AccessAllCaseInsensitive(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    access: ALL
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for access: ALL, got %d", len(f))
	}
}

func TestGL073_PublicWithSensitivePath(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    public: true
    paths:
      - config/credentials.json
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error for sensitive exposed path, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "credentials.json") {
		t.Errorf("expected sensitive path in message, got %q", f[0].Message)
	}
}

func TestGL073_AccessAllWithSensitivePath(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    access: all
    paths:
      - secrets/id_rsa
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error, got %s", f[0].Severity)
	}
}

func TestGL073_AccessDeveloper_NoFinding(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    access: developer
    paths:
      - build/
`)
	if len(f) != 0 {
		t.Errorf("access: developer is not anonymous exposure — expected no finding, got %d", len(f))
	}
}

func TestGL073_AccessNone_NoFinding(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    access: none
`)
	if len(f) != 0 {
		t.Errorf("access: none — expected no finding, got %d", len(f))
	}
}

func TestGL073_PublicFalse_NoFinding(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    public: false
    paths:
      - build/
`)
	if len(f) != 0 {
		t.Errorf("public: false — expected no finding, got %d", len(f))
	}
}

func TestGL073_AbsentExposure_NoFinding(t *testing.T) {
	f := findings073rule(t, `
build_job:
  artifacts:
    paths:
      - build/
    expire_in: 1 week
`)
	if len(f) != 0 {
		t.Errorf("no public/access key — expected no finding (default not flagged), got %d", len(f))
	}
}

func TestGL073_DefaultBlock(t *testing.T) {
	f := findings073rule(t, `
default:
  artifacts:
    public: true
    paths:
      - build/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding from default artifacts block, got %d", len(f))
	}
}

func TestGL073_NoArtifacts_NoFinding(t *testing.T) {
	f := findings073rule(t, `
build_job:
  script:
    - make build
`)
	if len(f) != 0 {
		t.Errorf("no artifacts — expected no finding, got %d", len(f))
	}
}

func TestGL073_JobNameSet(t *testing.T) {
	f := findings073rule(t, `
my_build:
  artifacts:
    access: all
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Job != "my_build" {
		t.Errorf("expected Job=my_build, got %q", f[0].Job)
	}
}
