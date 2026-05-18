package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings050(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL050.Check(doc.Root, "test.yml")
}

func TestGL050_SudoAptGet(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - sudo apt-get install -y nodejs
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL050_SudoMakeInstall(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - sudo make install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sudo make install, got %d", len(f))
	}
}

func TestGL050_NoSudoNoFinding(t *testing.T) {
	f := findings050(t, `
build:
  image: node:20.11.1
  script:
    - make install
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without sudo, got %d", len(f))
	}
}

func TestGL050_SubstringNoFinding(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - echo "pseudocode example"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for sudo as substring, got %d", len(f))
	}
}

func TestGL050_ShellCommentNoFinding(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - "# sudo apt-get install nodejs"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for sudo in shell comment, got %d", len(f))
	}
}

func TestGL050_SudoInBeforeScript(t *testing.T) {
	f := findings050(t, `
build:
  before_script:
    - sudo apt-get update
  script:
    - make build
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sudo in before_script, got %d", len(f))
	}
}

func TestGL050_SudoInAfterScript(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - make build
  after_script:
    - sudo rm -rf /tmp/build
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sudo in after_script, got %d", len(f))
	}
}

func TestGL050_GlobalBeforeScript(t *testing.T) {
	f := findings050(t, `
before_script:
  - sudo apt-get update

build:
  script:
    - make build
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sudo in global before_script, got %d", len(f))
	}
}

func TestGL050_JobNameInFinding(t *testing.T) {
	f := findings050(t, `
build-app:
  script:
    - sudo apt-get install -y build-essential
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Job != "build-app" {
		t.Errorf("expected job 'build-app', got %q", f[0].Job)
	}
}

func TestGL050_MultipleSudoLines(t *testing.T) {
	f := findings050(t, `
setup:
  script:
    - sudo apt-get update
    - sudo apt-get install -y nodejs
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for two sudo lines, got %d", len(f))
	}
}
