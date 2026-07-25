package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings081(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL081.Check(doc.Root, "test.yml")
}

func TestGL081_NoGuard(t *testing.T) {
	f := findings081(t, `
terraform-plan:
  stage: test
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com
  script:
    - terraform plan
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL081_AdmitsMergeRequest(t *testing.T) {
	f := findings081(t, `
aws-integration-test:
  stage: test
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  script:
    - aws sts assume-role-with-web-identity --web-identity-token "$AWS_ID_TOKEN"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for an MR-admitting guard, got %d", len(f))
	}
}

func TestGL081_IneffectiveRules(t *testing.T) {
	f := findings081(t, `
oidc-job:
  stage: test
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - when: on_success
  script:
    - ./run.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for rules with no if:, got %d", len(f))
	}
}

func TestGL081_RestrictedToDefaultBranch_NoFinding(t *testing.T) {
	f := findings081(t, `
deploy:
  stage: deploy
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a job restricted to the default branch, got %d", len(f))
	}
}

func TestGL081_RestrictedToTag_NoFinding(t *testing.T) {
	f := findings081(t, `
release:
  stage: deploy
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: '$CI_COMMIT_TAG'
  script:
    - ./release.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a tag-only guard, got %d", len(f))
	}
}

func TestGL081_RefProtected_NoFinding(t *testing.T) {
	f := findings081(t, `
deploy:
  stage: deploy
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: '$CI_COMMIT_REF_PROTECTED == "true"'
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when guarded on CI_COMMIT_REF_PROTECTED, got %d", len(f))
	}
}

func TestGL081_ExplicitBranchEquality_NoFinding(t *testing.T) {
	f := findings081(t, `
deploy:
  stage: deploy
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for explicit branch equality, got %d", len(f))
	}
}

func TestGL081_MRExcludedThenDefaultBranch_NoFinding(t *testing.T) {
	f := findings081(t, `
deploy:
  stage: deploy
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
      when: never
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when MRs are excluded with when: never, got %d", len(f))
	}
}

func TestGL081_NoIDTokens_NoFinding(t *testing.T) {
	f := findings081(t, `
deploy:
  stage: deploy
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a job without id_tokens:, got %d", len(f))
	}
}

func TestGL081_WorkflowRestrictsToProtected_Suppresses(t *testing.T) {
	f := findings081(t, `
workflow:
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

oidc-job:
  stage: test
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - ./run.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when workflow:rules restrict to protected refs, got %d", len(f))
	}
}

func TestGL081_WorkflowAdmitsMR_DoesNotSuppress(t *testing.T) {
	f := findings081(t, `
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

oidc-job:
  stage: test
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - ./run.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding — an MR-admitting workflow must not suppress, got %d", len(f))
	}
}

func TestGL081_OnlyMergeRequests(t *testing.T) {
	f := findings081(t, `
oidc-job:
  stage: test
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  only:
    - merge_requests
  script:
    - ./run.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for legacy only: merge_requests, got %d", len(f))
	}
}

func TestGL081_ExtendsSkipped(t *testing.T) {
	f := findings081(t, `
oidc-job:
  extends: .base
  stage: test
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - ./run.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a job using extends: (guard may be inherited), got %d", len(f))
	}
}

func TestGL081_HiddenJobSkipped(t *testing.T) {
	f := findings081(t, `
.oidc-template:
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - ./run.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a hidden (.-prefixed) template job, got %d", len(f))
	}
}

func TestGL081_MultipleJobs(t *testing.T) {
	f := findings081(t, `
aws-test:
  stage: test
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  script:
    - ./test.sh

vault-plan:
  stage: test
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com
  script:
    - ./plan.sh

deploy-prod:
  stage: deploy
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
  script:
    - ./deploy.sh
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (aws-test + vault-plan), got %d", len(f))
	}
}
