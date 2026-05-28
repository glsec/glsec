package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings065(t *testing.T, yaml string, allowed []string) []finding.Finding {
	t.Helper()
	r := &gl065{allowedRegistries: allowed}
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return r.Check(doc.Root, "test.yml")
}

func TestGL065_NoOpWhenUnset(t *testing.T) {
	f := findings065(t, `
build:
  image: docker.io/library/node:20
`, nil)
	if len(f) != 0 {
		t.Errorf("expected no findings when allowlist is empty, got %d", len(f))
	}
}

func TestGL065_DisallowedExplicitRegistry(t *testing.T) {
	f := findings065(t, `
build:
  image: docker.io/library/node:20
`, []string{"registry.example.com"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for docker.io image, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL065_AllowedExplicitRegistry(t *testing.T) {
	f := findings065(t, `
build:
  image: registry.example.com/node:20
`, []string{"registry.example.com"})
	if len(f) != 0 {
		t.Errorf("expected no finding for allowlisted registry, got %d", len(f))
	}
}

func TestGL065_BareImageResolvesToDockerHub(t *testing.T) {
	f := findings065(t, `
build:
  image: node:20
`, []string{"registry.example.com"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for bare image (docker.io), got %d", len(f))
	}
}

func TestGL065_DockerHubAllowed(t *testing.T) {
	f := findings065(t, `
build:
  image: node:20
`, []string{"docker.io"})
	if len(f) != 0 {
		t.Errorf("expected no finding when docker.io is allowlisted, got %d", len(f))
	}
}

func TestGL065_NamespacePrefixAllowed(t *testing.T) {
	f := findings065(t, `
build:
  image: ghcr.io/myorg/app:1.0.0
`, []string{"ghcr.io/myorg"})
	if len(f) != 0 {
		t.Errorf("expected no finding for image under allowed namespace, got %d", len(f))
	}
}

func TestGL065_NamespacePrefixOtherFlagged(t *testing.T) {
	f := findings065(t, `
build:
  image: ghcr.io/other/app:1.0.0
`, []string{"ghcr.io/myorg"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for image outside allowed namespace, got %d", len(f))
	}
}

func TestGL065_NamespacePrefixIsNotSubstring(t *testing.T) {
	f := findings065(t, `
build:
  image: ghcr.io/myorg-evil/app:1.0.0
`, []string{"ghcr.io/myorg"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding — myorg-evil is not under myorg, got %d", len(f))
	}
}

func TestGL065_DockerHubNamespacePrefix(t *testing.T) {
	clean := findings065(t, `
build:
  image: myorg/app:1.0.0
`, []string{"docker.io/myorg"})
	if len(clean) != 0 {
		t.Errorf("expected no finding for docker.io/myorg namespace, got %d", len(clean))
	}
	flagged := findings065(t, `
build:
  image: other/app:1.0.0
`, []string{"docker.io/myorg"})
	if len(flagged) != 1 {
		t.Fatalf("expected 1 finding for other docker.io namespace, got %d", len(flagged))
	}
}

func TestGL065_Services(t *testing.T) {
	f := findings065(t, `
build:
  image: registry.example.com/node:20
  services:
    - docker.io/library/postgres:16
    - name: registry.example.com/redis:7
`, []string{"registry.example.com"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for disallowed service, got %d", len(f))
	}
}

func TestGL065_VariableHostExempt(t *testing.T) {
	f := findings065(t, `
build:
  image: $REGISTRY/node:20
deploy:
  image: $MY_IMAGE
`, []string{"registry.example.com"})
	if len(f) != 0 {
		t.Errorf("expected no findings for variable registry hosts, got %d", len(f))
	}
}

func TestGL065_ResolvableHostWithVariablePath(t *testing.T) {
	f := findings065(t, `
build:
  image: docker.io/$IMAGE_NAME:latest
`, []string{"registry.example.com"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding — host docker.io is resolvable, got %d", len(f))
	}
}

func TestGL065_RegistryWithPort(t *testing.T) {
	clean := findings065(t, `
build:
  image: registry.example.com:5000/app:1.0
`, []string{"registry.example.com:5000"})
	if len(clean) != 0 {
		t.Errorf("expected no finding when host:port is allowlisted, got %d", len(clean))
	}
}

func TestGL065_DefaultImage(t *testing.T) {
	f := findings065(t, `
default:
  image: quay.io/org/tool:1.0
build:
  script: [make]
`, []string{"registry.example.com"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for default: image, got %d", len(f))
	}
}

func TestGL065_JobNameAttached(t *testing.T) {
	f := findings065(t, `
build:
  image: docker.io/library/node:20
`, []string{"registry.example.com"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Job != "build" {
		t.Errorf("expected job name 'build', got %q", f[0].Job)
	}
}
