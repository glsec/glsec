package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings062(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL062.Check(doc.Root, "test.yml")
}

func TestGL062_Printenv(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - printenv
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL062" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL062_BareEnv(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for bare env, got %d", len(f))
	}
}

func TestGL062_UsrBinEnv(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - /usr/bin/env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for /usr/bin/env, got %d", len(f))
	}
}

func TestGL062_PrintenvWithVarNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - printenv DEPLOY_ENV
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for printenv VAR, got %d", len(f))
	}
}

func TestGL062_EnvSetVarNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - env FOO=bar ./run.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for env VAR=v cmd, got %d", len(f))
	}
}

func TestGL062_EnvRunCommandNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - env python script.py
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for env <command>, got %d", len(f))
	}
}

func TestGL062_PrintenvWithSeparator(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - printenv && echo done
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 'printenv &&', got %d", len(f))
	}
}

func TestGL062_EnvAfterSemicolon(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - cd /tmp; env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for '; env', got %d", len(f))
	}
}

func TestGL062_CommentNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - "# printenv would leak everything"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}

func TestGL062_EnvironmentWordNotFlagged(t *testing.T) {
	f := findings062(t, `
debug:
  script:
    - environment_setup.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for word containing env, got %d", len(f))
	}
}
