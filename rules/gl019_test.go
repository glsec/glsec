package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings019(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL019.Check(doc.Root, "test.yml")
}

func TestGL019_DeployNoResourceGroup(t *testing.T) {
	f := findings019(t, `
deploy-prod:
  stage: deploy
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL019_EnvironmentNoResourceGroup(t *testing.T) {
	f := findings019(t, `
deploy:
  environment: production
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for environment job, got %d", len(f))
	}
}

func TestGL019_WithResourceGroup_NoFinding(t *testing.T) {
	f := findings019(t, `
deploy-prod:
  stage: deploy
  environment: production
  resource_group: production
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when resource_group is set, got %d", len(f))
	}
}

func TestGL019_BuildJob_NoFinding(t *testing.T) {
	f := findings019(t, `
build:
  stage: build
  script:
    - go build ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for build job, got %d", len(f))
	}
}

func TestGL019_TestJob_NoFinding(t *testing.T) {
	f := findings019(t, `
unit-tests:
  stage: test
  script:
    - go test ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for test job, got %d", len(f))
	}
}

func TestGL019_ReleaseStage(t *testing.T) {
	f := findings019(t, `
publish-pkg:
  stage: release
  script:
    - npm publish
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for release-stage job, got %d", len(f))
	}
}

func TestGL019_PublishStage(t *testing.T) {
	f := findings019(t, `
publish-image:
  stage: publish
  script:
    - docker push $CI_REGISTRY_IMAGE
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for publish-stage job, got %d", len(f))
	}
}

func TestGL019_MultipleDeployJobs(t *testing.T) {
	f := findings019(t, `
deploy-staging:
  stage: deploy
  resource_group: staging
  script: [./deploy.sh staging]

deploy-prod:
  environment: production
  script: [./deploy.sh prod]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (deploy-prod missing resource_group), got %d", len(f))
	}
}

func TestGL019_LineNumber(t *testing.T) {
	f := findings019(t, `
deploy-prod:
  stage: deploy
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
