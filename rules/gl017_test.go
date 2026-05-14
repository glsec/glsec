package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings017(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL017.Check(doc.Root, "test.yml")
}

func TestGL017_DeployNoTags(t *testing.T) {
	f := findings017(t, `
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

func TestGL017_EnvironmentNoTags(t *testing.T) {
	f := findings017(t, `
deploy:
  environment: production
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for environment job without tags, got %d", len(f))
	}
}

func TestGL017_DeployWithTags_NoFinding(t *testing.T) {
	f := findings017(t, `
deploy-prod:
  stage: deploy
  tags:
    - production
    - docker
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when tags are set, got %d", len(f))
	}
}

func TestGL017_EmptyTagsList(t *testing.T) {
	f := findings017(t, `
deploy-prod:
  stage: deploy
  tags: []
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for empty tags list, got %d", len(f))
	}
}

func TestGL017_BuildJobNoTags_NoFinding(t *testing.T) {
	f := findings017(t, `
build:
  stage: build
  script:
    - go build ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-deploy job without tags, got %d", len(f))
	}
}

func TestGL017_TestJobNoTags_NoFinding(t *testing.T) {
	f := findings017(t, `
unit-tests:
  stage: test
  script:
    - go test ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for test job without tags, got %d", len(f))
	}
}

func TestGL017_ReleaseStage(t *testing.T) {
	f := findings017(t, `
publish-pkg:
  stage: release
  script:
    - npm publish
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for release-stage job without tags, got %d", len(f))
	}
}

func TestGL017_PublishStage(t *testing.T) {
	f := findings017(t, `
publish-image:
  stage: publish
  script:
    - docker push $CI_REGISTRY_IMAGE
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for publish-stage job without tags, got %d", len(f))
	}
}

func TestGL017_MultipleJobs(t *testing.T) {
	f := findings017(t, `
build:
  stage: build
  script: [go build]

deploy-staging:
  stage: deploy
  script: [./deploy.sh staging]

deploy-prod:
  environment: production
  script: [./deploy.sh prod]
  tags:
    - prod-runner
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (deploy-staging has no tags), got %d", len(f))
	}
}

func TestGL017_LineNumber(t *testing.T) {
	f := findings017(t, `
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
