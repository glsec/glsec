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

func TestGL024_WindowsRunner_NoFinding(t *testing.T) {
	cases := map[string]string{
		"job tags": `
win:
  tags: [windows]
  script:
    - Get-ChildItem | Select-Object Name
`,
		"hosted runner tag": `
win:
  tags: [saas-windows-medium-amd64]
  script:
    - Get-ChildItem | Select-Object Name
`,
		"extends string": `
.win:
  tags: [Shared-Windows]
win:
  extends: .win
  script:
    - Get-ChildItem | Select-Object Name
`,
		"extends list, last wins": `
.linux:
  tags: [docker]
.win:
  tags: [windows-1809]
win:
  extends: [.linux, .win]
  script:
    - Get-ChildItem | Select-Object Name
`,
		"nested extends": `
.base:
  tags: [windows]
.mid:
  extends: .base
win:
  extends: .mid
  script:
    - Get-ChildItem | Select-Object Name
`,
		"default tags": `
default:
  tags: [windows]
win:
  script:
    - Get-ChildItem | Select-Object Name
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 0 {
				t.Errorf("expected no finding on a Windows runner, got %d", len(f))
			}
		})
	}
}

func TestGL024_NonWindowsRunner_StillReported(t *testing.T) {
	cases := map[string]string{
		"linux tags": `
build:
  tags: [docker, linux]
  script:
    - generate-config | tee config.yml
`,
		"job tags override windows default": `
default:
  tags: [windows]
build:
  tags: [docker]
  script:
    - generate-config | tee config.yml
`,
		"extends list, linux last": `
.win:
  tags: [windows]
.linux:
  tags: [docker]
build:
  extends: [.win, .linux]
  script:
    - generate-config | tee config.yml
`,
		"word inside another word": `
build:
  tags: [nowindowsrunner]
  script:
    - generate-config | tee config.yml
`,
		"cyclic extends": `
.a:
  extends: .b
.b:
  extends: .a
build:
  extends: .a
  script:
    - generate-config | tee config.yml
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 1 {
				t.Errorf("expected 1 finding, got %d", len(f))
			}
		})
	}
}

func TestGL024_InheritedPipefail_NoFinding(t *testing.T) {
	cases := map[string]string{
		"extends before_script": `
.base:
  before_script:
    - set -o pipefail
build:
  extends: .base
  script:
    - generate-config | tee config.yml
`,
		"nested extends": `
.base:
  before_script:
    - set -euo pipefail
.mid:
  extends: .base
build:
  extends: [.other, .mid]
  script:
    - generate-config | tee config.yml
`,
		"default before_script": `
default:
  before_script:
    - set -o pipefail
build:
  script:
    - generate-config | tee config.yml
`,
		"inherit default list with before_script": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    default: [before_script]
  script:
    - generate-config | tee config.yml
`,
		"top-level before_script": `
before_script:
  - set -o pipefail
build:
  script:
    - generate-config | tee config.yml
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 0 {
				t.Errorf("expected no finding, got %d", len(f))
			}
		})
	}
}

func TestGL024_InheritedPipefail_NotApplied(t *testing.T) {
	cases := map[string]string{
		"job overrides before_script": `
default:
  before_script:
    - set -o pipefail
build:
  before_script:
    - echo start
  script:
    - generate-config | tee config.yml
`,
		"inherit default false": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    default: false
  script:
    - generate-config | tee config.yml
`,
		"inherit default list without before_script": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    default: [image]
  script:
    - generate-config | tee config.yml
`,
		"after_script runs in its own shell": `
.base:
  after_script:
    - set -o pipefail
build:
  extends: .base
  script:
    - generate-config | tee config.yml
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 1 {
				t.Errorf("expected 1 finding, got %d", len(f))
			}
		})
	}
}
