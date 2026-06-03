package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings009(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL009.Check(doc.Root, "test.yml")
}

func TestGL009_GitLabInstanceAud(t *testing.T) {
	f := findings009(t, `
deploy:
  id_tokens:
    AWS_TOKEN:
      aud: "https://gitlab.example.com"
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL009_GitLabCom(t *testing.T) {
	f := findings009(t, `
deploy:
  id_tokens:
    TOKEN:
      aud: "https://gitlab.com"
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for gitlab.com, got %d", len(f))
	}
}

func TestGL009_ServiceSpecificAud_NoFinding(t *testing.T) {
	f := findings009(t, `
deploy:
  id_tokens:
    AWS_TOKEN:
      aud: "https://sts.amazonaws.com"
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for service-specific audience, got %d", len(f))
	}
}

func TestGL009_GCPAud_NoFinding(t *testing.T) {
	f := findings009(t, `
deploy:
  id_tokens:
    GCP_TOKEN:
      aud: "https://accounts.google.com"
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for GCP audience, got %d", len(f))
	}
}

func TestGL009_ListAud_OneOverbroad(t *testing.T) {
	f := findings009(t, `
deploy:
  id_tokens:
    TOKEN:
      aud:
        - "https://gitlab.example.com"
        - "https://sts.amazonaws.com"
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for list aud with one overbroad entry, got %d", len(f))
	}
}

func TestGL009_MultipleTokens(t *testing.T) {
	f := findings009(t, `
deploy:
  id_tokens:
    AWS_TOKEN:
      aud: "https://gitlab.example.com"
    GCP_TOKEN:
      aud: "https://gitlab.example.com"
  script: [./deploy.sh]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for two overbroad tokens, got %d", len(f))
	}
}

func TestGL009_VaultServiceSubdomain_NoFinding(t *testing.T) {
	// vault.gitlab.net is a Vault service audience, not the GitLab instance.
	f := findings009(t, `
deploy:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: "https://vault.gitlab.net"
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for service subdomain on a gitlab domain, got %d", len(f))
	}
}

func TestGL009_RegistrySubdomain_NoFinding(t *testing.T) {
	f := findings009(t, `
deploy:
  id_tokens:
    TOKEN:
      aud: "https://registry.gitlab.com"
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for registry subdomain, got %d", len(f))
	}
}

func TestGL009_NoIdTokens_NoFinding(t *testing.T) {
	f := findings009(t, `
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings when no id_tokens, got %d", len(f))
	}
}

func TestGL009_LineNumber(t *testing.T) {
	f := findings009(t, `
deploy:
  id_tokens:
    TOKEN:
      aud: "https://gitlab.example.com"
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
