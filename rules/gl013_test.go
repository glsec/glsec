package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings013(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL013.Check(doc.Root, "test.yml")
}

func TestGL013_ProdNoRules(t *testing.T) {
	f := findings013(t, `
deploy-prod:
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL013_ProdWithRules_NoFinding(t *testing.T) {
	f := findings013(t, `
deploy-prod:
  environment: production
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when rules: is present, got %d", len(f))
	}
}

func TestGL013_ProdWithOnly_NoFinding(t *testing.T) {
	f := findings013(t, `
deploy-prod:
  environment: production
  only:
    - main
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when only: is present, got %d", len(f))
	}
}

func TestGL013_EnvNameProdSubstring(t *testing.T) {
	f := findings013(t, `
deploy:
  environment: prod-eu-west
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 'prod-eu-west', got %d", len(f))
	}
}

func TestGL013_EnvNameLive(t *testing.T) {
	f := findings013(t, `
deploy:
  environment: live
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 'live', got %d", len(f))
	}
}

func TestGL013_EnvNameStaging(t *testing.T) {
	f := findings013(t, `
deploy:
  environment: staging
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 'staging', got %d", len(f))
	}
}

func TestGL013_EnvNameDev_NoFinding(t *testing.T) {
	f := findings013(t, `
deploy-dev:
  environment: development
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for dev environment, got %d", len(f))
	}
}

func TestGL013_MappingFormEnv(t *testing.T) {
	f := findings013(t, `
deploy-prod:
  environment:
    name: production
    url: https://example.com
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mapping environment form, got %d", len(f))
	}
}

func TestGL013_MappingFormWithRules_NoFinding(t *testing.T) {
	f := findings013(t, `
deploy-prod:
  environment:
    name: production
    url: https://example.com
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for mapping env with rules:, got %d", len(f))
	}
}

func TestGL013_DeploymentTierProduction(t *testing.T) {
	f := findings013(t, `
deploy:
  environment:
    name: my-app
    deployment_tier: production
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for deployment_tier: production with non-prod name, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "deployment_tier: production") {
		t.Errorf("expected tier in message, got %q", f[0].Message)
	}
}

func TestGL013_DeploymentTierStaging(t *testing.T) {
	f := findings013(t, `
deploy:
  environment:
    name: eu-west
    deployment_tier: staging
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for deployment_tier: staging, got %d", len(f))
	}
}

func TestGL013_DeploymentTierWithRules_NoFinding(t *testing.T) {
	f := findings013(t, `
deploy:
  environment:
    name: my-app
    deployment_tier: production
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when rules: present, got %d", len(f))
	}
}

func TestGL013_DeploymentTierDevelopment_NoFinding(t *testing.T) {
	f := findings013(t, `
deploy:
  environment:
    name: my-app
    deployment_tier: development
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for deployment_tier: development with non-prod name, got %d", len(f))
	}
}

func TestGL013_DeploymentTierNoName(t *testing.T) {
	f := findings013(t, `
deploy:
  environment:
    deployment_tier: production
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for tier-only environment, got %d", len(f))
	}
}

func TestGL013_NoEnvironment_NoFinding(t *testing.T) {
	f := findings013(t, `
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for job without environment:, got %d", len(f))
	}
}

func TestGL013_CaseInsensitive(t *testing.T) {
	f := findings013(t, `
deploy:
  environment: PRODUCTION
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for uppercase PRODUCTION, got %d", len(f))
	}
}

func TestGL013_LineNumber(t *testing.T) {
	f := findings013(t, `
deploy-prod:
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
