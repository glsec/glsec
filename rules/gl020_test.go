package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings020(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL020.Check(doc.Root, "test.yml")
}

func TestGL020_CurlOThenExecute(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - tar xzf tool.tar.gz
    - ./tool install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL020_CurlOutputFlag(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSL -o tool.sh https://example.com/install.sh
    - bash tool.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for -o flag, got %d", len(f))
	}
}

func TestGL020_WgetNoChecksum(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - wget https://example.com/tool.tar.gz
    - tar xzf tool.tar.gz
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for wget without checksum, got %d", len(f))
	}
}

func TestGL020_WithSha256sum_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - echo "abc123def456  tool.tar.gz" | sha256sum -c
    - tar xzf tool.tar.gz
    - ./tool install
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when sha256sum is present, got %d", len(f))
	}
}

func TestGL020_WithShasum_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - shasum -a 256 -c checksums.txt
    - tar xzf tool.tar.gz
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when shasum is present, got %d", len(f))
	}
}

func TestGL020_WithGpgVerify_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - curl -sSLO https://example.com/tool.tar.gz.sig
    - gpg --verify tool.tar.gz.sig tool.tar.gz
    - tar xzf tool.tar.gz
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when gpg --verify is present, got %d", len(f))
	}
}

func TestGL020_WithCosignVerify_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - cosign verify tool.tar.gz
    - tar xzf tool.tar.gz
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when cosign verify is present, got %d", len(f))
	}
}

func TestGL020_CurlPipeBash_NoFinding(t *testing.T) {
	// GL011 territory — direct pipe, not a save-then-execute pattern
	f := findings020(t, `
install:
  script:
    - curl -sSL https://example.com/install.sh | bash
`)
	if len(f) != 0 {
		t.Errorf("expected no GL020 finding for direct curl|bash (covered by GL011), got %d", len(f))
	}
}

func TestGL020_NoCurlWget_NoFinding(t *testing.T) {
	f := findings020(t, `
build:
  script:
    - go build ./...
    - tar xzf prebuilt.tar.gz
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when no curl/wget present, got %d", len(f))
	}
}

func TestGL020_ChecksumInBeforeScript_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  before_script:
    - curl -sSLO https://example.com/tool.tar.gz
    - sha256sum -c checksums.txt
  script:
    - ./tool install
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when sha256sum is in before_script, got %d", len(f))
	}
}

func TestGL020_OneFindinPerJob(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool1.tar.gz
    - curl -sSLO https://example.com/tool2.tar.gz
    - tar xzf tool1.tar.gz && tar xzf tool2.tar.gz
`)
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 finding per job (not per download), got %d", len(f))
	}
}

func TestGL020_LineNumber(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - ./tool install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
