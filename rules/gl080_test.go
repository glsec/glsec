// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings080(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL080.Check(doc.Root, "test.yml")
}

func TestGL080_DeployNoGuard(t *testing.T) {
	f := findings080(t, `
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

func TestGL080_IneffectiveRules(t *testing.T) {
	f := findings080(t, `
publish:
  stage: deploy
  rules:
    - when: on_success
  script:
    - ./publish.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for rules with no if:, got %d", len(f))
	}
}

func TestGL080_EffectiveIfRule_NoFinding(t *testing.T) {
	f := findings080(t, `
deploy:
  stage: deploy
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push"'
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a rules:if guard, got %d", len(f))
	}
}

func TestGL080_ChangesRule_NoFinding(t *testing.T) {
	f := findings080(t, `
deploy:
  stage: deploy
  rules:
    - changes:
        - src/**/*
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a rules:changes condition, got %d", len(f))
	}
}

func TestGL080_OnlyClause_NoFinding(t *testing.T) {
	f := findings080(t, `
deploy:
  stage: deploy
  only:
    - main
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for an only: clause, got %d", len(f))
	}
}

func TestGL080_NonSensitiveJob_NoFinding(t *testing.T) {
	f := findings080(t, `
run-tests:
  stage: test
  script:
    - make test
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a non-sensitive job, got %d", len(f))
	}
}

func TestGL080_EnvironmentMakesSensitive(t *testing.T) {
	f := findings080(t, `
ship-it:
  stage: build
  environment:
    name: review/$CI_COMMIT_REF_SLUG
  script:
    - ./ship.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for an environment job with no guard, got %d", len(f))
	}
}

func TestGL080_WorkflowRulesSuppress(t *testing.T) {
	f := findings080(t, `
workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push"'

deploy-prod:
  stage: deploy
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when workflow:rules restricts the source, got %d", len(f))
	}
}

func TestGL080_DefersToGL013(t *testing.T) {
	// Production environment with no rules: is GL013's case — GL080 must not
	// also fire on it.
	f := findings080(t, `
deploy-prod:
  stage: deploy
  environment:
    name: production
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected GL080 to defer to GL013 for prod env + no rules, got %d", len(f))
	}
}

func TestGL080_HiddenJobSkipped(t *testing.T) {
	f := findings080(t, `
.deploy_template:
  stage: deploy
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a hidden (.-prefixed) template job, got %d", len(f))
	}
}

func TestGL080_ExtendsSkipped(t *testing.T) {
	f := findings080(t, `
deploy-prod:
  extends: .deploy_base
  stage: deploy
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a job using extends: (guard may be inherited), got %d", len(f))
	}
}

func TestGL080_MergeKeyGuardResolved(t *testing.T) {
	f := findings080(t, `
.base: &base
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push"'

deploy-prod:
  <<: *base
  stage: deploy
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when the guard is merged in via <<:, got %d", len(f))
	}
}

func TestGL080_MergeKeyWithoutGuard(t *testing.T) {
	f := findings080(t, `
.base: &base
  image: alpine:3.24

deploy-prod:
  <<: *base
  stage: deploy
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Errorf("expected a finding when the merged base carries no guard, got %d", len(f))
	}
}

func TestGL080_MergeInsideRulesItemEffective(t *testing.T) {
	f := findings080(t, `
.if-main: &if-main
  if: '$CI_COMMIT_BRANCH == "main"'

deploy-prod:
  stage: deploy
  rules:
    - <<: *if-main
      variables:
        X: "1"
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when a rules item merges its condition via <<:, got %d", len(f))
	}
}

func TestGL080_EmptyEnvironmentNotSensitive(t *testing.T) {
	f := findings080(t, `
run-tests:
  stage: test
  environment:
  script:
    - make test
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for an empty environment: on a test job, got %d", len(f))
	}
}

func TestGL080_EnvironmentStopNotSensitive(t *testing.T) {
	f := findings080(t, `
stop-review:
  stage: deploy
  environment:
    name: review/$CI_COMMIT_REF_SLUG
    action: stop
  script:
    - ./teardown.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for an environment teardown (action: stop) job, got %d", len(f))
	}
}

func TestGL080_ReleaseBuildNotFlagged(t *testing.T) {
	f := findings080(t, `
windows-release-build:
  stage: build
  script:
    - cmake --build . --config Release
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a release *build* job, got %d", len(f))
	}
}

func TestGL080_MultipleJobs(t *testing.T) {
	f := findings080(t, `
build-app:
  stage: build
  script:
    - make

deploy-prod:
  stage: deploy
  script:
    - ./deploy.sh

publish:
  stage: deploy
  rules:
    - when: always
  script:
    - ./publish.sh
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (deploy-prod + publish), got %d", len(f))
	}
}

// A Pages job in a deploy stage is GL013's; GL080 must not report it twice.
func TestGL080_DefersPagesToGL013(t *testing.T) {
	f := findings080(t, `
pages:
  stage: deploy
  script: [mkdocs build -d public]
`)
	if len(f) != 0 {
		t.Errorf("expected GL080 to defer the Pages job to GL013, got %d", len(f))
	}
	f = findings080(t, `
pages:
  stage: deploy
  pages:
    path_prefix: review
  script: [mkdocs build -d public]
`)
	if len(f) != 1 {
		t.Errorf("expected GL080 to keep a prefixed Pages deploy, got %d", len(f))
	}
}

// rules: from a !reference into an included file are unknown and count as a
// guard, for GL080 and GL081 (#979).
func TestGL080_UnresolvedReferenceRules(t *testing.T) {
	for _, rulesYAML := range []string{
		"  rules:\n    - !reference [.default_rules, rules]\n",
		"  rules: !reference [.default_rules, rules]\n",
	} {
		src := "include:\n  - project: example/ci-templates\n    ref: 0123456789abcdef0123456789abcdef01234567\n    file: /rules.yml\npublish:\n  stage: deploy\n" + rulesYAML +
			"  id_tokens:\n    CLOUD_TOKEN:\n      aud: https://example.com\n  script: [./publish.sh]\n"
		doc, err := parser.Parse([]byte(src), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if f := append(GL080.Check(doc.Root, "test.yml"), GL081.Check(doc.Root, "test.yml")...); len(f) != 0 {
			t.Errorf("%q: got %v, want no finding", rulesYAML, f)
		}
	}
	// A reference that resolves in the file is read as before.
	doc, err := parser.Parse([]byte(".r:\n  rules:\n    - when: always\npublish:\n  stage: deploy\n  rules:\n    - !reference [.r, rules]\n  script: [./publish.sh]\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if f := GL080.Check(doc.Root, "test.yml"); len(f) != 1 {
		t.Errorf("resolved reference to a condition-less rule: got %v, want one finding", f)
	}
}
