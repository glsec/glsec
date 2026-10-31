// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

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

func TestGL019_DevTierEnvironment_NoFinding(t *testing.T) {
	for _, tier := range []string{"development", "testing"} {
		f := findings019(t, `
review:
  environment:
    name: review/mr-$CI_MERGE_REQUEST_IID
    deployment_tier: `+tier+`
  script:
    - ./preview.sh
`)
		if len(f) != 0 {
			t.Errorf("%s: expected no finding, got %+v", tier, f)
		}
	}
}

func TestGL019_StagingTierEnvironment(t *testing.T) {
	f := findings019(t, `
review:
  environment:
    name: staging
    deployment_tier: staging
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected a staging environment to count, got %+v", f)
	}
}

// An environment that says the job deploys nothing lasting decides on its
// own; the stage name only counts for jobs without one. A pre-release stage
// is no release stage (#1052).
func TestGL019_EnvironmentDecidesOverStage(t *testing.T) {
	for _, tc := range []struct {
		name, job string
		want017   int
		want019   int
	}{
		{"explicit development tier", "  stage: deploy\n  environment:\n    name: review/$CI_COMMIT_REF_SLUG\n    deployment_tier: development\n", 1, 0},
		{"guessed review tier", "  stage: deploy\n  environment: review/$CI_COMMIT_REF_SLUG\n", 1, 1},
		{"guessed tier, no deploy stage", "  stage: test\n  environment: review/$CI_COMMIT_REF_SLUG\n", 1, 0},
		{"explicit testing tier", "  stage: release\n  environment:\n    name: staging\n    deployment_tier: testing\n", 1, 0},
		{"action prepare", "  stage: deploy\n  environment:\n    name: production\n    action: prepare\n", 1, 0},
		{"production in deploy stage", "  stage: deploy\n  environment: production\n", 1, 1},
		{"prerelease stage", "  stage: prerelease\n", 0, 0},
		{"pre-release stage", "  stage: pre-release\n", 0, 0},
		{"pre_release stage", "  stage: Pre_Release\n", 0, 0},
		{"release stage", "  stage: release\n", 1, 1},
		{"prerelease then release", "  stage: prerelease-and-release\n", 1, 1},
	} {
		src := "stages: [build, test, deploy, release, prerelease, pre-release, Pre_Release, prerelease-and-release]\njob:\n" + tc.job + "  script: [./run.sh]\n"
		doc, err := parser.Parse([]byte(src), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL017.Check(doc.Root, "test.yml")); got != tc.want017 {
			t.Errorf("%s: GL017 got %d findings, want %d", tc.name, got, tc.want017)
		}
		if got := len(GL019.Check(doc.Root, "test.yml")); got != tc.want019 {
			t.Errorf("%s: GL019 got %d findings, want %d", tc.name, got, tc.want019)
		}
	}
}
