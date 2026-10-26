// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

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

func TestGL013_Pages(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"job named pages", `
pages:
  script: [mkdocs build -d public]
  artifacts:
    paths: [public]
`, 1},
		{"pages: true on another job", `
docs:
  pages: true
  script: [mkdocs build -d public]
`, 1},
		{"pages: mapping without prefix", `
docs:
  pages:
    expire_in: 1 week
  script: [mkdocs build -d public]
`, 1},
		{"pages: neither a scalar nor a mapping", `
docs:
  pages: [public]
  script: [mkdocs build -d public]
`, 0},
		{"pages job with non-prod environment", `
pages:
  environment: docs
  script: [mkdocs build -d public]
`, 1},
		{"guarded by rules", `
pages:
  script: [mkdocs build -d public]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
`, 0},
		{"guarded by only", `
pages:
  script: [mkdocs build -d public]
  only: [main]
`, 0},
		{"parallel deployment with path_prefix", `
pages:
  pages:
    path_prefix: "$CI_COMMIT_REF_SLUG"
  script: [mkdocs build -d public]
`, 0},
		{"pages: false", `
pages:
  pages: false
  script: [mkdocs build -d public]
`, 0},
		{"hidden template", `
.pages:
  pages: true
  script: [mkdocs build -d public]
`, 0},
		{"extends a base that may carry the guard", `
pages:
  extends: .docs
  script: [mkdocs build -d public]
`, 0},
		{"other job without pages", `
docs:
  script: [mkdocs build -d public]
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := findings013(t, tc.yaml)
			if len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(f), f)
			}
			if tc.want == 1 && !strings.Contains(f[0].Message, "GitLab Pages") {
				t.Errorf("unexpected message: %s", f[0].Message)
			}
		})
	}
}

func TestGL013_WorkflowRestrictsToProtected(t *testing.T) {
	jobs := `
pages:
  script: [mkdocs build -d public]
deploy:
  environment: production
  script: [./deploy.sh]
`
	quiet := []string{
		"workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n",
		"workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - if: $CI_COMMIT_TAG\n",
		"workflow:\n  rules:\n    - if: $CI_COMMIT_REF_PROTECTED == \"true\"\n",
	}
	for _, wf := range quiet {
		if f := findings013(t, wf+jobs); len(f) != 0 {
			t.Errorf("expected no findings with %q, got %d", wf, len(f))
		}
	}
	loud := []string{
		"workflow:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n",
		"workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n",
		"workflow:\n  rules:\n    - when: always\n",
	}
	for _, wf := range loud {
		if f := findings013(t, wf+jobs); len(f) != 2 {
			t.Errorf("expected 2 findings with %q, got %d", wf, len(f))
		}
	}
}

func TestGL013_Inheritance(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"guard from extends", `
.main-only:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
deploy:
  extends: .main-only
  environment: production
  script: [./deploy.sh]
`, 0},
		{"guard two levels up", `
.guard:
  only: [main]
.deploy:
  extends: .guard
deploy:
  extends: [.deploy]
  environment: production
  script: [./deploy.sh]
`, 0},
		{"environment from extends, no guard", `
.prod:
  environment: production
deploy:
  extends: .prod
  script: [./deploy.sh]
`, 1},
		{"hidden template is not reported", `
.prod:
  environment: production
  script: [./deploy.sh]
`, 0},
		{"base in another file", `
deploy:
  extends: .from-included-file
  environment: production
  script: [./deploy.sh]
`, 0},
		{"pages: true from extends", `
.pages:
  pages: true
docs:
  extends: .pages
  script: [mkdocs build -d public]
`, 1},
		{"path_prefix from extends", `
.review:
  pages:
    path_prefix: review
pages:
  extends: .review
  script: [mkdocs build -d public]
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings013(t, tc.yaml); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(f), f)
			}
		})
	}
}

func TestGL013_InheritedEnvironmentReportsTheJob(t *testing.T) {
	f := findings013(t, `
.prod:
  environment: production
deploy:
  extends: .prod
  script: [./deploy.sh]
`)
	if len(f) != 1 || f[0].Line != 4 {
		t.Fatalf("expected one finding on the job's line 4, got %v", f)
	}
}
