// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

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

func TestGL049_NameKeywordInTestStage_NoFinding(t *testing.T) {
	f := findings049(t, `
fuzz migrations:
  stage: test
  interruptible: true
  script: [npm run fuzz-migrations]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for a name-keyword job in a check-only stage, got %d: %v", len(f), f)
	}
}

func TestGL049_NameKeywordInTestStage_StillFlagged(t *testing.T) {
	f := findings049(t, `
fuzz migrations:
  stage: test
  interruptible: true
  environment: production
  script: [npm run fuzz-migrations]
run migrations:
  stage: deploy
  interruptible: true
  script: [./migrate up]
ship it:
  stage: build
  interruptible: true
  script: [./ship.sh]
`)
	if len(f) != 3 {
		t.Fatalf("expected 3 findings (environment job, deploy-stage job, build-stage name job), got %d: %v", len(f), f)
	}
}

func TestGL049_InheritedFromHiddenTemplate(t *testing.T) {
	f := findings049(t, `
.deploy:
  stage: deploy
  interruptible: true
  script:
    - kubectl apply -f k8s/

deploy-production:
  extends: .deploy
`)
	if len(f) != 1 || f[0].Job != "deploy-production" || f[0].Line != 4 {
		t.Fatalf("expected one finding for deploy-production on the template's interruptible line, got %+v", f)
	}
}

func TestGL049_InterruptibleFromDefault(t *testing.T) {
	f := findings049(t, `
default:
  interruptible: true

deploy-production:
  stage: deploy
  script:
    - kubectl apply -f k8s/
`)
	if len(f) != 1 {
		t.Fatalf("expected default: interruptible to count, got %+v", f)
	}
}

func TestGL049_DevTierEnvironment_NoFinding(t *testing.T) {
	f := findings049(t, `
review:
  interruptible: true
  environment:
    name: review/mr-$CI_MERGE_REQUEST_IID
    deployment_tier: development
  script:
    - ./preview.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for a development environment, got %+v", f)
	}
}

func TestGL049_DevTierDeployStage(t *testing.T) {
	f := findings049(t, `
review:
  stage: deploy
  interruptible: true
  environment:
    name: review/mr-$CI_MERGE_REQUEST_IID
    deployment_tier: testing
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected the deploy stage to still count, got %+v", f)
	}
}

func TestGL049_OwnKeysWithTemplateFromAnotherFile(t *testing.T) {
	f := findings049(t, `
server-image:
  extends: .kaniko-template
  stage: release
  interruptible: true
  environment:
    name: server-image
`)
	if len(f) != 1 {
		t.Fatalf("expected the job's own keys to count, got %+v", f)
	}
}

// A build-only job in a release/dist stage, and a job disabled by
// rules: all when: never, are not interruptible-deploy concerns; a real deploy
// (environment, or a deploy verb in the script) still is (#1104).
func TestGL049_BuildOnlyAndDisabled(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"build-only in release stage", `
d:
  stage: release
  interruptible: true
  script: [meson dist]
`, 0},
		{"cargo build in release stage", `
b:
  stage: release
  interruptible: true
  script: [cargo build --release]
`, 0},
		{"disabled by when never", `
deploy:
  interruptible: true
  rules:
    - when: never
  script: [kubectl apply -f k8s/]
`, 0},
		{"real deploy by script in release stage", `
d:
  stage: release
  interruptible: true
  script: [kubectl apply -f k8s/]
`, 1},
		{"real deploy by environment", `
d:
  environment: production
  interruptible: true
  script: [./run.sh]
`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings049(t, tc.yaml); len(f) != tc.want {
				t.Errorf("got %d findings, want %d: %+v", len(f), tc.want, f)
			}
		})
	}
}
