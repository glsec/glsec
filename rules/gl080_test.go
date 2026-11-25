// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
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

func TestGL080_RequiresDeploySignal(t *testing.T) {
	// A deploy-sounding name alone, with no credential and no real deploy, is
	// not sensitive; a real deploy/publish/infra-apply command is, regardless
	// of the job name (#1371). Jobs are unguarded, so a sensitive one fires.
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"deploy echo placeholder", "deploy-example:\n  stage: deploy\n  script: [echo \"do your deploy here\"]", 0},
		{"release writes a note", "release:\n  script: [echo hi >> notes.md]", 0},
		{"dotnet publish is a local build", "publish-app:\n  script: [dotnet publish -o out]", 0},
		{"provision builds an image", "provision-img:\n  script: [./build-super-img.sh]", 0},
		{"terraform apply, not named deploy", "infra:\n  script: [terraform apply -auto-approve]", 1},
		{"pulumi up", "stack:\n  script: [pulumi up --yes]", 1},
		{"kubectl apply", "k8s:\n  script: [kubectl apply -f k8s/]", 1},
		{"helm upgrade install", "chart:\n  script: [helm upgrade --install app ./chart]", 1},
		{"npm publish", "publish:\n  script: [npm publish]", 1},
		{"dotnet nuget push", "nuget:\n  script: [dotnet nuget push pkg.nupkg -s https://nuget.org -k $K]", 1},
		{"custom deploy with a credential", "deploy:\n  script: ['./deploy.sh \"$DEPLOY_TOKEN\"']", 1},
		{"release name with a credential variable", "release:\n  variables:\n    PROD_DEPLOY_KEY: x\n  script: [./ship]", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings080(t, "\n"+tc.yaml+"\n"); len(f) != tc.want {
				t.Errorf("got %d findings, want %d: %+v", len(f), tc.want, f)
			}
		})
	}
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

func TestGL080_NonProductionEnvironmentNotOwnedByGL013(t *testing.T) {
	f := findings080(t, "deploy:\n  stage: deploy\n  environment: non-prod\n  script: [./deploy.sh]\n")
	if len(f) != 1 {
		t.Fatalf("expected one GL080 finding, got %v", f)
	}
}

func TestGL080_ProductionNameAfterNonProductionWord(t *testing.T) {
	f := findings080(t, "deploy_non_prod_live:\n  stage: deploy\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n  script: [./deploy.sh]\n")
	if len(f) != 1 {
		t.Fatalf("expected one finding for live, got %v", f)
	}
}

func TestGL080_ManualOnly_FlaggedWithManualWording(t *testing.T) {
	f := findings080(t, `
deploy-dev-manual:
  stage: deploy
  environment:
    name: dev
  when: manual
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a when: manual deploy job, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "when: manual") ||
		!strings.Contains(f[0].Message, "fork merge request") {
		t.Errorf("expected manual-gate wording, got %q", f[0].Message)
	}
	if strings.Contains(f[0].Message, "no rules:/only:/except: guard") {
		t.Errorf("manual job should not use the generic no-guard wording: %q", f[0].Message)
	}
}

func TestGL080_ManualInRulesItem_FlaggedWithManualWording(t *testing.T) {
	f := findings080(t, `
publish:
  stage: deploy
  rules:
    - when: manual
  script:
    - ./publish.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "when: manual") {
		t.Errorf("expected manual-gate wording, got %q", f[0].Message)
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

// changes: alone is true for every new branch and in pipelines without a push
// event, so it is no restriction (#1498; it counted as one since #381).
func TestGL080_ChangesRule(t *testing.T) {
	f := findings080(t, `
deploy:
  stage: deploy
  rules:
    - changes:
        - src/**/*
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Errorf("expected 1 finding for a rules:changes-only entry, got %d", len(f))
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
    name: edge-cluster
  script:
    - ./ship.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for an environment job with no guard, got %d", len(f))
	}
}

// A development or testing environment, or one made per branch, commit or
// merge request, is not a deploy signal on its own; a per-run name GitLab
// guesses as production still is. A real deploy command keeps the job
// sensitive whatever its environment (#1497).
func TestGL080_EphemeralEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, env, script string
		want              int
	}{
		{"review app per branch", "review/$CI_COMMIT_REF_SLUG", "make docs", 0},
		{"braced per-MR name", "mr-${CI_MERGE_REQUEST_IID}", "make docs", 0},
		{"guessed development", "dev", "env | sort", 0},
		{"guessed testing", "qa", "make test", 0},
		{"other tier", "edge-cluster", "make", 1},
		{"dev environment with a real deploy", "dev", "kubectl apply -f k8s/", 1},
		{"review app with a fixed image push", "review/$CI_COMMIT_REF_SLUG", "docker push registry.example.com/app:latest", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings080(t, "job:\n  stage: build\n  environment:\n    name: "+tc.env+"\n  script:\n    - "+tc.script+"\n")
			if len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(f), f)
			}
		})
	}
	for env, want := range map[string]bool{
		"review/$CI_COMMIT_REF_SLUG":       true,
		"{name: dev}":                      true,
		"{name: prod/$CI_COMMIT_REF_SLUG}": false,
		"{name: review/$CI_COMMIT_REF_SLUG, deployment_tier: production}": false,
		"{name: edge, deployment_tier: development}":                      true,
		"staging":                        false,
		"{name: staging/$CI_COMMIT_SHA}": true,
		"production":                     false,
	} {
		doc := parseDoc(t, "environment: "+env+"\n")
		if got := ephemeralEnvironment(parser.FindKey(parser.Unwrap(doc), "environment")); got != want {
			t.Errorf("ephemeralEnvironment(%s) = %v, want %v", env, got, want)
		}
	}
}

// Only a workflow that admits protected refs only keeps an unguarded job off
// other branches. One that admits every push, or GitLab's recommended switch
// between branch and merge request pipelines, doesn't (#1492).
func TestGL080_WorkflowRulesSuppress(t *testing.T) {
	job := "deploy-prod:\n  stage: deploy\n  script:\n    - kubectl apply -f k8s/\n"
	for name, tc := range map[string]struct {
		workflow string
		want     int
	}{
		"push":                 {"workflow:\n  rules:\n    - if: '$CI_PIPELINE_SOURCE == \"push\"'\n", 1},
		"any branch":           {"workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n", 1},
		"branch/MR switch":     {"workflow:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS\n      when: never\n    - if: $CI_COMMIT_BRANCH\n", 1},
		"default branch":       {"workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n", 0},
		"default branch, tag":  {"workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - if: $CI_COMMIT_TAG\n", 0},
		"protected":            {"workflow:\n  rules:\n    - if: $CI_COMMIT_REF_PROTECTED == \"true\"\n", 0},
		"unresolved reference": {"workflow:\n  rules:\n    - if: $CI_COMMIT_TAG\n    - !reference [.included, rules]\n", 1},
	} {
		t.Run(name, func(t *testing.T) {
			if f := findings080(t, tc.workflow+job); len(f) != tc.want {
				t.Errorf("got %d findings, want %d: %v", len(f), tc.want, f)
			}
		})
	}
}

// A push or publish that ships nothing another branch depends on is not a
// deploy: an image pushed under a tag made from the run, or a dry run
// (#1492). latest, fixed tags and versions still are.
func TestGL080_EphemeralPushAndDryRun(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		vars         string
		want         int
	}{
		{"push ref slug", "docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG", "", 0},
		{"push short sha braced", "docker push ${CI_REGISTRY_IMAGE}/app:${CI_COMMIT_SHORT_SHA}", "", 0},
		{"push pipeline id with podman", "podman push $CI_REGISTRY_IMAGE/dev:${CI_PIPELINE_ID}-perl", "", 0},
		{"push via job variable", "docker push $IMAGE_TAG", "  variables:\n    IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA\n", 0},
		{"image push subcommand", "docker image push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA", "", 0},
		{"buildah push", "buildah push $CI_REGISTRY_IMAGE:$CI_JOB_ID", "", 0},
		{"kubectl dry run", "kubectl apply --dry-run=client -f k8s/", "", 0},
		{"npm publish dry run", "npm publish --dry-run", "", 0},
		{"dart pub publish -n", "dart pub publish -n", "", 0},
		// Still sensitive.
		{"push latest", "docker push $CI_REGISTRY_IMAGE:latest", "", 1},
		{"push without tag", "docker push $CI_REGISTRY_IMAGE", "", 1},
		{"push version", "docker push $CI_REGISTRY_IMAGE:1.2.3", "", 1},
		{"push tag from tag pipeline", "docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_TAG", "", 1},
		{"push all tags", "docker push --all-tags $CI_REGISTRY_IMAGE", "", 1},
		{"push unresolved variable", "docker push $IMAGE", "", 1},
		{"push via variable to latest", "docker push $IMAGE", "  variables:\n    IMAGE: $CI_REGISTRY_IMAGE:latest\n", 1},
		{"ephemeral push, then latest", "docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA && docker push $CI_REGISTRY_IMAGE:latest", "", 1},
		{"kubectl dry run none", "kubectl apply --dry-run=none -f k8s/", "", 1},
		{"kubectl apply", "kubectl apply -f k8s/", "", 1},
		{"npm publish", "npm publish", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y := "ship:\n  stage: build\n" + tc.vars + "  script:\n    - " + fmt.Sprintf("%q", tc.script) + "\n"
			if f := findings080(t, y); len(f) != tc.want {
				t.Errorf("got %d findings, want %d: %v\n%s", len(f), tc.want, f, y)
			}
		})
	}
	// A file-level variable resolves too.
	if f := findings080(t, "variables:\n  IMG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG\nship:\n  script:\n    - docker push $IMG\n"); len(f) != 0 {
		t.Errorf("global variable: got %v, want none", f)
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

func TestGL080_MergeRequestOnlyProduction(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"deploy_prod on MR to master", `
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "master"
  before_script:
    - cat "$PROD_SSH" | ssh-add -
  script:
    - scp build.tgz deploy@prod.example.invalid:.
`, 1},
		{"only: merge_requests, live in the stage", `
release:
  stage: go-live
  only: [merge_requests]
  script:
    - ./release.sh
`, 1},
		{"MR IID gate with workflow admitting MRs", `
workflow:
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
deploy-production:
  stage: deploy
  rules:
    - if: $CI_MERGE_REQUEST_IID
  script:
    - ./deploy.sh
`, 1},
		{"npm publish from MR pipelines", `
publish:
  stage: publish
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    NPM_CONFIG_REGISTRY: https://registry.npmjs.org/
  script:
    - npm publish --tag next
`, 1},
		{"twine upload to PyPI from MR pipelines", `
pypi:
  stage: deploy
  rules:
    - if: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == $CI_DEFAULT_BRANCH
  script:
    - twine upload dist/*
`, 1},
		{"no production signal", `
deploy_review:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./deploy.sh
`, 0},
		{"publish_preview without publish command", `
publish_preview:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./upload-preview.sh
`, 0},
		{"preprod is not production", `
deploy-preprod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./deploy.sh
`, 0},
		{"pre-prod is not production", `
deploy-pre-prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./deploy.sh
`, 0},
		{"rule also admits the default branch", `
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - ./deploy.sh
`, 0},
		{"MR rule is when: never, then a branch rule", `
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      when: never
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script:
    - ./deploy.sh
`, 0},
		{"production environment is GL013's", `
deploy_prod:
  stage: deploy
  environment: production
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./deploy.sh
`, 0},
		{"TestPyPI upload", `
pypi:
  stage: deploy
  rules:
    - if: $CI_MERGE_REQUEST_IID
  script:
    - twine upload --repository testpypi dist/*
`, 0},
		{"GitLab package registry via job token", `
publish:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    TWINE_PASSWORD: $CI_JOB_TOKEN
    TWINE_USERNAME: gitlab-ci-token
  script:
    - twine upload --repository-url "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/pypi" dist/*
`, 0},
		{"dry-run publish", `
publish:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - npm publish --dry-run
`, 0},
		{"TestPyPI URL in variables", `
pypi:
  stage: deploy
  rules:
    - if: $CI_MERGE_REQUEST_IID
  variables:
    TWINE_REPOSITORY_URL:
      value: https://test.pypi.org/legacy/
  script:
    - twine upload dist/*
`, 0},
		{"workflow with a catch-all rule admits MRs", `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
      when: never
    - if: $CI_COMMIT_TAG
    - when: always
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./deploy.sh
`, 1},
		{"workflow rule from an included !reference admits MRs", `
workflow:
  rules:
    - if: $CI_COMMIT_TAG
    - !reference [.included, rules]
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./deploy.sh
`, 1},
		{"workflow keeps MR pipelines out", `
workflow:
  rules:
    - if: $CI_COMMIT_BRANCH
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ./deploy.sh
`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings080(t, tc.yaml)
			if len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(f), tc.want, f)
			}
			if tc.want == 1 && !strings.Contains(f[0].Message, "runs only in merge request pipelines") {
				t.Errorf("unexpected message: %s", f[0].Message)
			}
		})
	}
}

// GitLab reads a mapping in order, so the merged rules replace the guard
// written above the <<: (#1152).
func TestGL080_RulesOverriddenByMergeKey(t *testing.T) {
	const src = `
.always: &always
  rules:
    - when: always

deploy-prod:
  stage: deploy
  %s
  script:
    - ./deploy.sh
`
	guard := "rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH"
	if f := findings080(t, fmt.Sprintf(src, guard+"\n  <<: *always")); len(f) != 1 {
		t.Errorf("guard above the <<: is replaced: got %v", f)
	}
	if f := findings080(t, fmt.Sprintf(src, "<<: *always\n  "+guard)); len(f) != 0 {
		t.Errorf("guard below the <<: stays: got %v", f)
	}
}

// A guard with an entry that has no if: restricts nothing: GitLab runs the job
// by the first entry that matches. Only entries without if: count; an if:
// that tests a branch is set, or admits merge requests, is not reported
// here (#1498).
func TestGL080_FallbackEntry(t *testing.T) {
	push := "  script:\n    - docker push \"$CI_REGISTRY_IMAGE:latest\"\n"
	for _, tc := range []struct {
		name, rules string
		want        int
	}{
		{"manual fallback", "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: manual\n", 1},
		{"on_success fallback", "    - if: $CI_COMMIT_TAG\n    - when: on_success\n", 1},
		{"changes only", "    - changes: [Dockerfile]\n", 1},
		{"exists only", "    - exists: [Dockerfile]\n", 1},
		{"never fallback", "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: never\n", 0},
		{"protected only", "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n", 0},
		{"branch presence is not counted", "    - if: $CI_COMMIT_BRANCH\n", 0},
		{"merge request entry is not counted", "    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n", 0},
		{"exclusion before the fallback", "    - if: $CI_COMMIT_REF_PROTECTED != \"true\"\n      when: never\n    - when: manual\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings080(t, "deploy-image:\n"+push+"  rules:\n"+tc.rules)
			if len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(f), f)
			}
		})
	}
	if f := findings080(t, "build:\n  script:\n    - make\n  rules:\n    - changes: [src/**/*]\n"); len(f) != 0 {
		t.Fatalf("a job that isn't sensitive must not be reported, got %v", f)
	}
	if f := findings080(t, "workflow:\n  rules:\n    - if: $CI_COMMIT_TAG\ndeploy-image:\n"+push+"  rules:\n    - when: manual\n"); len(f) != 0 {
		t.Fatalf("a protected-only workflow silences the file, got %v", f)
	}
}

func TestGL080_FallbackAfterExclusion(t *testing.T) {
	f := findings080(t, `
deploy-image:
  script:
    - docker push "$CI_REGISTRY_IMAGE:latest"
  rules:
    - if: $CI_PIPELINE_SOURCE != "pipeline" && $MERGE_SYNC_TRIGGER != "1"
      when: never
    - when: on_success
`)
	if len(f) != 0 {
		t.Fatalf("a fallback after an exclusion glsec can't read must not be reported, got %v", f)
	}
}
