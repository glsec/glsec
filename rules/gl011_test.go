package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings011(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL011.Check(doc.Root, "test.yml")
}

func TestGL011_CurlPipeBash(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -sSL https://install.example.com/setup.sh | bash
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
}

func TestGL011_WgetPipeSh(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - wget -qO- https://example.com/install.sh | sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for wget | sh, got %d", len(f))
	}
}

func TestGL011_CurlPipePython(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -s https://bootstrap.example.com | python3
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for curl | python3, got %d", len(f))
	}
}

func TestGL011_ProcessSubstitution(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - python3 <(curl -s https://example.com/bootstrap.py)
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for process substitution, got %d", len(f))
	}
}

func TestGL011_CurlPipeBase64Bash(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -s https://example.com/script | base64 -d | bash
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for curl | base64 | bash, got %d", len(f))
	}
}

func TestGL011_CommandSubstitutionBash(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - bash -c "$(curl -sSL https://example.com/install.sh)"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for bash -c $(curl ...), got %d", len(f))
	}
}

func TestGL011_CommandSubstitutionSh(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - sh -c "$(wget -qO- https://example.com/install.sh)"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sh -c $(wget ...), got %d", len(f))
	}
}

func TestGL011_InlineBase64DecodeBash(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - echo "ZWNobyBwd25lZAo=" | base64 -d | bash
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for echo | base64 -d | bash, got %d", len(f))
	}
}

func TestGL011_DownloadThenExecAnd(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -fsSL https://example.com/install.sh -o install.sh && bash install.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for curl -o file && bash file, got %d", len(f))
	}
}

func TestGL011_RedirectThenExecSemicolon(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -fsSL https://example.com/payload.sh > install.sh; sh install.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for curl > file; sh file, got %d", len(f))
	}
}

func TestGL011_PipeInsideQuotedString_NoFinding(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - 'echo "to install run curl https://x.sh | bash yourself"'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for | bash inside a quoted string, got %d", len(f))
	}
}

func TestGL011_ChecksumVerifiedThenExec_NoFinding(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -fsSL https://example.com/install.sh -o install.sh && sha256sum -c install.sh.sha256 && bash install.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when checksum is verified before exec, got %d", len(f))
	}
}

func TestGL011_CurlDownloadOnly_NoFinding(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -sSLO https://install.example.com/setup.sh
    - bash setup.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when curl downloads without pipe, got %d", len(f))
	}
}

func TestGL011_CurlPipeJq_NoFinding(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -s https://api.example.com/data | jq '.version'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for curl | jq, got %d", len(f))
	}
}

func TestGL011_CurlPipeGrep_NoFinding(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -s https://example.com/check | grep "version"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for curl | grep, got %d", len(f))
	}
}

func TestGL011_BeforeScript(t *testing.T) {
	f := findings011(t, `
setup:
  before_script:
    - curl -sSL https://example.com/setup.sh | bash
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL011_TopLevelBeforeScript(t *testing.T) {
	f := findings011(t, `
before_script:
  - curl -sSL https://example.com/setup.sh | bash

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in top-level before_script, got %d", len(f))
	}
}

func TestGL011_LineNumber(t *testing.T) {
	f := findings011(t, `
setup:
  script:
    - curl -sSL https://example.com/setup.sh | bash
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
