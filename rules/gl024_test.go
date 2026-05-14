package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings024(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL024.Check(doc.Root, "test.yml")
}

func TestGL024_PipeWithoutPipefail(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - generate-config | tee config.yml
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL024_PipefailSet_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - set -o pipefail
    - generate-config | tee config.yml
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when pipefail is set, got %d", len(f))
	}
}

func TestGL024_PipefailInline_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - set -o pipefail && generate-config | tee config.yml
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when pipefail set inline, got %d", len(f))
	}
}

func TestGL024_SetEuoPipefail_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - set -euo pipefail
    - generate-config | tee config.yml
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for set -euo pipefail, got %d", len(f))
	}
}

func TestGL024_LogicalOr_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - cmd || true
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for || (logical OR), got %d", len(f))
	}
}

func TestGL024_PipeAndLogicalOr(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - generate-config | tee config.yml || true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (real pipe present despite ||), got %d", len(f))
	}
}

func TestGL024_NoPipe_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - go build ./...
    - go test ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for script without pipes, got %d", len(f))
	}
}

func TestGL024_PipefailInBeforeScript_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  before_script:
    - set -o pipefail
  script:
    - generate-config | tee config.yml
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when pipefail set in before_script, got %d", len(f))
	}
}

func TestGL024_OneFindingPerJob(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - cmd1 | tee out1.txt
    - cmd2 | tee out2.txt
    - cmd3 | tee out3.txt
`)
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 finding per job (at first pipe), got %d", len(f))
	}
}

func TestGL024_MultipleJobs(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - set -o pipefail
    - cmd | tee out.txt

test:
  script:
    - cmd | tee out.txt
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (only test job), got %d", len(f))
	}
}

func TestGL024_LineNumber(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - generate-config | tee config.yml
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
