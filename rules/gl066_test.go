package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings066(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL066.Check(doc.Root, "test.yml")
}

func TestGL066_InlineCredentials(t *testing.T) {
	f := findings066(t, `
variables:
  DOCKER_AUTH_CONFIG: '{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for inline DOCKER_AUTH_CONFIG, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity, got %s", f[0].Severity)
	}
}

func TestGL066_VariableReference_NoFinding(t *testing.T) {
	f := findings066(t, `
variables:
  DOCKER_AUTH_CONFIG: $REGISTRY_AUTH
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for variable reference, got %d", len(f))
	}
}

func TestGL066_BracedVariableReference_NoFinding(t *testing.T) {
	f := findings066(t, `
variables:
  DOCKER_AUTH_CONFIG: ${REGISTRY_AUTH}
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for braced variable reference, got %d", len(f))
	}
}

func TestGL066_ExtendedForm(t *testing.T) {
	f := findings066(t, `
variables:
  DOCKER_AUTH_CONFIG:
    value: '{"auths":{"reg.example.com":{"auth":"dXNlcjpwYXNz"}}}'
    description: registry auth
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for extended-form inline creds, got %d", len(f))
	}
}

func TestGL066_PerJobVariables(t *testing.T) {
	f := findings066(t, `
build:
  variables:
    DOCKER_AUTH_CONFIG: '{"auths":{"r.example.com":{"auth":"dXNlcjpwYXNz"}}}'
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in job variables, got %d", len(f))
	}
	if f[0].Job != "build" {
		t.Errorf("expected job name 'build', got %q", f[0].Job)
	}
}

func TestGL066_DefaultVariables(t *testing.T) {
	f := findings066(t, `
default:
  image: node:20
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when DOCKER_AUTH_CONFIG absent, got %d", len(f))
	}
}

func TestGL066_OtherVariableIgnored(t *testing.T) {
	f := findings066(t, `
variables:
  SOME_CONFIG: '{"auths":{"reg":{"auth":"x"}}}'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-DOCKER_AUTH_CONFIG variable, got %d", len(f))
	}
}

func TestGL066_AuthKeyOnly(t *testing.T) {
	f := findings066(t, `
variables:
  DOCKER_AUTH_CONFIG: '{"auth":"dXNlcjpwYXNz"}'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for bare auth key, got %d", len(f))
	}
}

func TestGL066_NonCredentialValue_NoFinding(t *testing.T) {
	f := findings066(t, `
variables:
  DOCKER_AUTH_CONFIG: ""
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for empty value, got %d", len(f))
	}
}
