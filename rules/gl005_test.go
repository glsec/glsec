package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings005(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL005.Check(doc.Root, "test.yml")
}

func TestGL005_EnvFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .env file, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_PemFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - deploy-key.pem
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .pem file, got %d", len(f))
	}
}

func TestGL005_NoExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing expire_in, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity for missing expiry")
	}
}

func TestGL005_SensitiveAndNoExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
      - dist/
`)
	// .env finding (Error) + no expire_in (Warn)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL005_SafeArtifactWithExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/
      - coverage.xml
    expire_in: 7 days
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for safe artifact with expiry, got %d", len(f))
	}
}

func TestGL005_KeyFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - secrets/api.key
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .key file, got %d", len(f))
	}
}

func TestGL005_SecretInPath(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - output/db_password.txt
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for password in filename, got %d", len(f))
	}
}

func TestGL005_TerraformState(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - terraform.tfstate
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for tfstate, got %d", len(f))
	}
}

func TestGL005_DefaultBlockSensitivePath(t *testing.T) {
	f := findings005(t, `
default:
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sensitive path in default: artifacts:, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_DefaultBlockNoExpiry(t *testing.T) {
	f := findings005(t, `
default:
  artifacts:
    paths:
      - dist/

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing expire_in in default: artifacts:, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL005_NoArtifacts(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings when no artifacts block, got %d", len(f))
	}
}

func TestGL005_LineNumbers(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
