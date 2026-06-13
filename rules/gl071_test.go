package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings071(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL071.Check(doc.Root, "test.yml")
}

func TestGL071_ManualGateBeforeProdDeploy(t *testing.T) {
	f := findings071(t, `
stages: [build, approve, deploy]
approve_prod:
  stage: approve
  when: manual
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for optional manual gate, got %d", len(f))
	}
	if f[0].Job != "approve_prod" {
		t.Errorf("expected finding on approve_prod, got %q", f[0].Job)
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL071_AllowFailureFalse_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [build, approve, deploy]
approve_prod:
  stage: approve
  when: manual
  allow_failure: false
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("explicit allow_failure: false is blocking — expected no finding, got %d", len(f))
	}
}

func TestGL071_WhenManualInRules_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [build, approve, deploy]
approve_prod:
  stage: approve
  rules:
    - when: manual
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("when: manual inside rules is blocking by default — expected no finding, got %d", len(f))
	}
}

func TestGL071_NoLaterDeploy_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [build, test, cleanup]
teardown:
  stage: cleanup
  when: manual
  script: [./teardown.sh]
`)
	if len(f) != 0 {
		t.Errorf("manual job with no later prod deploy — expected no finding, got %d", len(f))
	}
}

func TestGL071_DeployBeforeGate_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [deploy, approve]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
approve_prod:
  stage: approve
  when: manual
  script: [echo approved]
`)
	if len(f) != 0 {
		t.Errorf("deploy is not in a later stage than the gate — expected no finding, got %d", len(f))
	}
}

func TestGL071_ManualDeployItself_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [build, deploy]
deploy_prod:
  stage: deploy
  environment: production
  when: manual
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("a manual deploy job is legitimate — expected no finding, got %d", len(f))
	}
}

func TestGL071_GateBeforeNonProdDeploy_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [build, approve, deploy]
approve:
  stage: approve
  when: manual
  script: [echo approved]
deploy_review:
  stage: deploy
  environment: review/feature-1
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("deploy target is not production — expected no finding, got %d", len(f))
	}
}

func TestGL071_GateSameStageAsDeploy_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [build, deploy]
approve_prod:
  stage: deploy
  when: manual
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("gate is in the same stage as the deploy — expected no finding, got %d", len(f))
	}
}

func TestGL071_HiddenTemplate_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [build, approve, deploy]
.approve_template:
  stage: approve
  when: manual
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("hidden job templates do not run — expected no finding, got %d", len(f))
	}
}

func TestGL071_AllowFailureTrueExplicit_StillFlagged(t *testing.T) {
	f := findings071(t, `
stages: [build, approve, deploy]
approve_prod:
  stage: approve
  when: manual
  allow_failure: true
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("explicit allow_failure: true is still optional — expected 1 finding, got %d", len(f))
	}
}

func TestGL071_DefaultStages(t *testing.T) {
	// No stages: declared — default order is .pre, build, test, deploy, .post.
	f := findings071(t, `
approve_prod:
  stage: test
  when: manual
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding using default stage order, got %d", len(f))
	}
}

func TestGL071_NonManualJob_NoFinding(t *testing.T) {
	f := findings071(t, `
stages: [build, approve, deploy]
approve_prod:
  stage: approve
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`)
	if len(f) != 0 {
		t.Errorf("job is not manual — expected no finding, got %d", len(f))
	}
}
