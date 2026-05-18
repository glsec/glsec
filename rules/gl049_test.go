package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings049(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL049.Check(doc.Root, "test.yml")
}

func TestGL049_DeployJobInterruptibleTrue(t *testing.T) {
	f := findings049(t, `
deploy-production:
  stage: deploy
  interruptible: true
  script:
    - kubectl apply -f k8s/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL049_DeployJobInterruptibleFalse(t *testing.T) {
	f := findings049(t, `
deploy-production:
  stage: deploy
  interruptible: false
  script:
    - kubectl apply -f k8s/
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for interruptible: false, got %d", len(f))
	}
}

func TestGL049_DeployJobNoInterruptible(t *testing.T) {
	f := findings049(t, `
deploy-production:
  stage: deploy
  script:
    - kubectl apply -f k8s/
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when interruptible is absent, got %d", len(f))
	}
}

func TestGL049_BuildJobInterruptibleTrueNoFinding(t *testing.T) {
	f := findings049(t, `
build:
  stage: build
  interruptible: true
  script:
    - make build
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for non-deploy job with interruptible: true, got %d", len(f))
	}
}

func TestGL049_ReleaseJobNameMatch(t *testing.T) {
	f := findings049(t, `
release-binaries:
  interruptible: true
  script:
    - goreleaser release
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for release job name, got %d", len(f))
	}
}

func TestGL049_PublishJobNameMatch(t *testing.T) {
	f := findings049(t, `
publish-npm:
  interruptible: true
  script:
    - npm publish
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for publish job name, got %d", len(f))
	}
}

func TestGL049_MigrateJobNameMatch(t *testing.T) {
	f := findings049(t, `
run-migrations:
  interruptible: true
  script:
    - ./migrate up
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for migrate in job name, got %d", len(f))
	}
}

func TestGL049_EnvironmentKeyMatch(t *testing.T) {
	f := findings049(t, `
push-to-prod:
  environment: production
  interruptible: true
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for job with environment key, got %d", len(f))
	}
}

func TestGL049_JobNameInFinding(t *testing.T) {
	f := findings049(t, `
deploy-prod:
  interruptible: true
  script:
    - kubectl apply -f k8s/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Job != "deploy-prod" {
		t.Errorf("expected job 'deploy-prod', got %q", f[0].Job)
	}
}

func TestGL049_TestJobInterruptibleTrueNoFinding(t *testing.T) {
	f := findings049(t, `
unit-tests:
  stage: test
  interruptible: true
  script:
    - go test ./...
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for test job with interruptible: true, got %d", len(f))
	}
}
