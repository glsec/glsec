// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

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

func TestGL009_TokenExchange_NoFinding(t *testing.T) {
	f := findings009(t, `
publish:
  id_tokens:
    EXCHANGE_TOKEN:
      aud: https://gitlab.com/api/v4/token_exchange
      target_audience: gitlab-artifact-registry
    EXCHANGE_SELF_MANAGED:
      aud: https://gitlab.example.com/api/v4/token_exchange
      target_audience: gitlab-artifact-registry
  script: [./publish.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a target_audience token exchange, got %d", len(f))
	}
}

func TestGL009_TokenExchange_StillReported(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: YAML fixtures, no credentials
		"exchange endpoint without target_audience": `
publish:
  id_tokens:
    T:
      aud: https://gitlab.com/api/v4/token_exchange
  script: [./publish.sh]
`,
		"other path without target_audience": `
publish:
  id_tokens:
    T:
      aud: https://gitlab.example.com/some/other/path
  script: [./publish.sh]
`,
		"empty target_audience": `
publish:
  id_tokens:
    T:
      aud: https://gitlab.com
      target_audience: ""
  script: [./publish.sh]
`,
		"target_audience on a sibling token only": `
publish:
  id_tokens:
    EXCHANGE:
      aud: https://gitlab.com/api/v4/token_exchange
      target_audience: gitlab-artifact-registry
    CLOUD:
      aud: https://gitlab.com
  script: [./publish.sh]
`,
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings009(t, y); len(f) != 1 {
				t.Errorf("expected 1 finding, got %d", len(f))
			}
		})
	}
}
