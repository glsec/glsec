package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings003(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL003.Check(doc.Root, "test.yml")
}

func TestGL003_LocalInclude(t *testing.T) {
	f := findings003(t, `
include:
  - local: '/templates/security.yml'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for local include, got %d", len(f))
	}
}

func TestGL003_TemplateInclude(t *testing.T) {
	f := findings003(t, `
include:
  - template: 'Security/SAST.gitlab-ci.yml'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for template include, got %d", len(f))
	}
}

func TestGL003_ScalarShorthand(t *testing.T) {
	f := findings003(t, `
include: '/templates/security.yml'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for scalar shorthand include, got %d", len(f))
	}
}

func TestGL003_RemoteInclude(t *testing.T) {
	f := findings003(t, `
include:
  - remote: 'https://example.com/templates/security.yml'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for remote include, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL003_ProjectMissingRef(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing ref, got %d", len(f))
	}
}

func TestGL003_ProjectMutableRef(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
    ref: main
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mutable ref, got %d", len(f))
	}
}

func TestGL003_ProjectPinnedTag(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
    ref: v1.2.3
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for pinned tag, got %d", len(f))
	}
}

func TestGL003_ProjectPinnedSHA(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
    ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for SHA-pinned ref, got %d", len(f))
	}
}

func TestGL003_ComponentMutableRef(t *testing.T) {
	f := findings003(t, `
include:
  - component: 'gitlab.com/my-org/my-component/build@main'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for component with mutable ref, got %d", len(f))
	}
}

func TestGL003_ComponentPinnedVersion(t *testing.T) {
	f := findings003(t, `
include:
  - component: 'gitlab.com/my-org/my-component/build@1.0.0'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for versioned component, got %d", len(f))
	}
}

func TestGL003_ComponentMissingRef(t *testing.T) {
	f := findings003(t, `
include:
  - component: 'gitlab.com/my-org/my-component/build'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for component missing version, got %d", len(f))
	}
}

func TestGL003_Mixed(t *testing.T) {
	f := findings003(t, `
include:
  - local: '/safe.yml'
  - project: 'company/templates'
    file: '/deploy.yml'
    ref: main
  - remote: 'https://example.com/template.yml'
  - template: 'SAST.gitlab-ci.yml'
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (mutable ref + remote), got %d", len(f))
	}
}

func TestGL003_LineNumbers(t *testing.T) {
	f := findings003(t, `
include:
  - remote: 'https://example.com/template.yml'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
