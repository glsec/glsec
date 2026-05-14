package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings012(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL012.Check(doc.Root, "test.yml")
}

func TestGL012_DeployStageWhenAlways(t *testing.T) {
	f := findings012(t, `
deploy-production:
  stage: deploy
  when: always
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL012_EnvironmentWhenAlways(t *testing.T) {
	f := findings012(t, `
release:
  when: always
  environment: production
  script: [./release.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for job with environment:, got %d", len(f))
	}
}

func TestGL012_ReleaseStage(t *testing.T) {
	f := findings012(t, `
publish-npm:
  stage: release
  when: always
  script: [npm publish]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for release stage, got %d", len(f))
	}
}

func TestGL012_DeploySubstring(t *testing.T) {
	f := findings012(t, `
job:
  stage: deploy-production
  when: always
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for stage containing 'deploy', got %d", len(f))
	}
}

func TestGL012_WhenOnSuccess_NoFinding(t *testing.T) {
	f := findings012(t, `
deploy-production:
  stage: deploy
  when: on_success
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for when: on_success, got %d", len(f))
	}
}

func TestGL012_NoWhen_NoFinding(t *testing.T) {
	f := findings012(t, `
deploy-production:
  stage: deploy
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when when: is absent, got %d", len(f))
	}
}

func TestGL012_TestStageExcluded_NoFinding(t *testing.T) {
	// when: always in test stage is sometimes intentional (e.g. report upload)
	f := findings012(t, `
upload-report:
  stage: test
  when: always
  script: [./upload.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for test stage, got %d", len(f))
	}
}

func TestGL012_BuildStageExcluded_NoFinding(t *testing.T) {
	f := findings012(t, `
cleanup:
  stage: build
  when: always
  script: [./cleanup.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for build stage, got %d", len(f))
	}
}

func TestGL012_UnknownStageNoEnvironment_NoFinding(t *testing.T) {
	f := findings012(t, `
notify:
  stage: notify
  when: always
  script: [./notify.sh]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-deploy stage without environment:, got %d", len(f))
	}
}

func TestGL012_LineNumber(t *testing.T) {
	f := findings012(t, `
deploy-production:
  stage: deploy
  when: always
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
