package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings067(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL067.Check(doc.Root, "test.yml")
}

func TestGL067_OverridePrefix(t *testing.T) {
	f := findings067(t, `
variables:
  SECURE_ANALYZERS_PREFIX: registry.attacker.example/analyzers
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for off-registry prefix, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL067_DefaultRegistryPrefix_NoFinding(t *testing.T) {
	f := findings067(t, `
variables:
  SECURE_ANALYZERS_PREFIX: registry.gitlab.com/security-products
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when prefix stays on registry.gitlab.com, got %d", len(f))
	}
}

func TestGL067_Unset_NoFinding(t *testing.T) {
	f := findings067(t, `
variables:
  FOO: bar
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when SECURE_ANALYZERS_PREFIX is unset, got %d", len(f))
	}
}

func TestGL067_TemplateRegistryHostVariable_NoFinding(t *testing.T) {
	f := findings067(t, `
variables:
  SECURE_ANALYZERS_PREFIX: $CI_TEMPLATE_REGISTRY_HOST/security-products
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for variable-driven host, got %d", len(f))
	}
}

func TestGL067_WholeVariableReference_NoFinding(t *testing.T) {
	f := findings067(t, `
variables:
  SECURE_ANALYZERS_PREFIX: $INTERNAL_PREFIX
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for whole-variable reference, got %d", len(f))
	}
}

func TestGL067_AnalyzerImageOverride(t *testing.T) {
	f := findings067(t, `
variables:
  CS_ANALYZER_IMAGE: registry.attacker.example/container-scanning:7
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for off-registry analyzer image, got %d", len(f))
	}
}

func TestGL067_AnalyzerImageOnOfficialRegistry_NoFinding(t *testing.T) {
	f := findings067(t, `
variables:
  SAST_ANALYZER_IMAGE: registry.gitlab.com/security-products/semgrep:5
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for analyzer image on registry.gitlab.com, got %d", len(f))
	}
}

func TestGL067_ExtendedForm(t *testing.T) {
	f := findings067(t, `
variables:
  SECURE_ANALYZERS_PREFIX:
    value: registry.attacker.example/analyzers
    description: internal mirror
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for extended-form override, got %d", len(f))
	}
}

func TestGL067_PerJobVariables(t *testing.T) {
	f := findings067(t, `
sast:
  variables:
    SECURE_ANALYZERS_PREFIX: registry.attacker.example/analyzers
  script: [/analyzer run]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in job variables, got %d", len(f))
	}
	if f[0].Job != "sast" {
		t.Errorf("expected job name 'sast', got %q", f[0].Job)
	}
}

func TestGL067_DefaultVariables(t *testing.T) {
	f := findings067(t, `
default:
  variables:
    SECURE_ANALYZERS_PREFIX: registry.attacker.example/analyzers
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in default variables, got %d", len(f))
	}
}

func TestGL067_HTTPSchemePrefix(t *testing.T) {
	f := findings067(t, `
variables:
  SECURE_ANALYZERS_PREFIX: https://registry.attacker.example/analyzers
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for scheme-prefixed host, got %d", len(f))
	}
}
