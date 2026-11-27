// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
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
    - docker push registry.example.com/app:latest
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

// A weak deploy signal is reported as info, a strong one as warn (#1548).
func TestGL080_SignalSeverity(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       finding.Severity
	}{
		{"deploy-named script", "deploy-prod:\n  stage: deploy\n  script: [./deploy.sh]\n", finding.Info},
		{"keyword and credential", "release:\n  variables:\n    PROD_DEPLOY_KEY: x\n  script: [./ship]\n", finding.Info},
		{"bare verb", "d:\n  script: [make deploy]\n", finding.Info},
		{"rsync", "d:\n  script: [rsync -a public/ web@host:/srv/www/]\n", finding.Info},
		{"scp", "d:\n  script: [scp app.tgz web@host:/srv/]\n", finding.Info},
		{"git push", "d:\n  script: [git push origin HEAD:release]\n", finding.Info},
		{"docker push", "d:\n  script: [docker push registry.example.com/app:latest]\n", finding.Warn},
		{"twine", "d:\n  script: [twine upload dist/*]\n", finding.Warn},
		{"kubectl", "d:\n  script: [kubectl apply -f k8s/]\n", finding.Warn},
		{"semantic-release", "d:\n  script: [npx semantic-release]\n", finding.Warn},
		{"environment", "d:\n  environment: eu-central\n  script: [./deploy.sh]\n", finding.Warn},
		{"weak and strong", "d:\n  script:\n    - rsync -a public/ web@host:/srv/www/\n    - docker push registry.example.com/app:latest\n", finding.Warn},
		{"push in compound if", "d:\n  script:\n    - |\n      if [[ $CI_COMMIT_BRANCH == \"master\" && $NS == \"org\" ]]; then\n        docker push img:tag\n      fi\n", finding.Info},
		{"push in case", "d:\n  script:\n    - 'case $CREATE in true) twine upload dist/*;; esac'\n", finding.Info},
		{"push after test and", "d:\n  script:\n    - '[ \"$PUSH\" = 1 ] && docker push img:tag'\n", finding.Info},
		{"push after test or", "d:\n  script:\n    - 'test -z \"$SKIP\" || docker push img:tag'\n", finding.Info},
		{"push in PowerShell if", "d:\n  script:\n    - 'if ($env:CI_COMMIT_BRANCH -eq \"main\" -and $env:X) { docker push img:tag }'\n", finding.Info},
		{"push after fi", "d:\n  script:\n    - 'if [ -n \"$X\" ]; then echo x; fi; docker push img:tag'\n", finding.Warn},
		{"push in for loop", "d:\n  script:\n    - 'for t in a b; do docker push img:$t; done'\n", finding.Warn},
		{"push after build and", "d:\n  script:\n    - 'docker build -t img:tag . && docker push img:tag'\n", finding.Warn},
		{"if word in a string", "d:\n  script:\n    - echo \"if this fails\"\n    - docker push img:tag\n", finding.Warn},
		{"conditional and unconditional", "d:\n  script:\n    - 'if [ -n \"$X\" ]; then docker push img:a; fi'\n    - docker push img:b\n", finding.Warn},
		{"strong only in echo", "d:\n  script:\n    - echo docker push registry.example.com/app:latest\n    - rsync -a public/ web@host:/srv/www/\n", finding.Info},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings080(t, tc.yaml)
			if len(f) != 1 || f[0].Severity != tc.want {
				t.Fatalf("want one %s finding, got %+v", tc.want, f)
			}
		})
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
    - helm upgrade --install app ./chart
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
		if got := ephemeralEnvironmentIn(parser.FindKey(parser.Unwrap(doc), "environment"), nil, nil); got != want {
			t.Errorf("ephemeralEnvironmentIn(%s) = %v, want %v", env, got, want)
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
		{"per-run variable with a suffix", "docker push \"$IMG-debug\"", "  variables:\n    IMG: $CI_REGISTRY_IMAGE/pipeline:$CI_PIPELINE_ID\n", 0},
		{"per-run tag through a variable chain", "docker push $IMG", "  variables:\n    TAG: dev-$CI_COMMIT_SHORT_SHA\n    IMG: $CI_REGISTRY_IMAGE:$TAG\n", 0},
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

func TestGL080_LocalCluster(t *testing.T) {
	chartTest := `
test-charts:
  services: [docker:dind]
  before_script:
    - kind create cluster --wait 60s
  script:
    - helm install app charts/app
    - helm test app
`
	if f := findings080(t, chartTest); len(f) != 0 {
		t.Errorf("chart test in a kind cluster: got %v, want none", f)
	}
	deploy := `
deploy-chart:
  script:
    - helm upgrade --install app charts/app
`
	if f := findings080(t, deploy); len(f) != 1 {
		t.Errorf("helm upgrade without a local cluster: got %d findings, want 1", len(f))
	}
	mixed := `
test-and-push:
  before_script:
    - kind create cluster
  script:
    - helm install app charts/app
    - docker push $CI_REGISTRY_IMAGE:latest
`
	if f := findings080(t, mixed); len(f) != 1 {
		t.Errorf("local cluster plus a latest push: got %d findings, want 1", len(f))
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
		{"protected MR source (#1543)", `
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_SOURCE_BRANCH_PROTECTED == "true" && $CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID
  script:
    - scp build.tgz deploy@prod.example.invalid:.
`, 0},
		{"protected MR source, maybe a fork (#1543)", `
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_SOURCE_BRANCH_PROTECTED == "true"
  script:
    - scp build.tgz deploy@prod.example.invalid:.
`, 1},
		{"approved MR stays reported (#1543)", `
deploy_prod:
  stage: deploy
  rules:
    - if: $CI_MERGE_REQUEST_APPROVED == "true"
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

func TestGL080_ShellGuards(t *testing.T) {
	fallback := "  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: manual\n"
	for _, tc := range []struct {
		name, job string
		want      int
	}{
		{"latest push in an if on main", fallback + `  script:
    - docker push "$CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG"
    - if [ "$CI_COMMIT_BRANCH" = "main" ]; then docker push "$CI_REGISTRY_IMAGE:latest"; fi
`, 0},
		{"multi-line if on the default branch", fallback + `  script:
    - |
      if [[ "$CI_COMMIT_BRANCH" == "$CI_DEFAULT_BRANCH" ]]; then
        docker push "$CI_REGISTRY_IMAGE:latest"
      fi
`, 0},
		{"protected test with &&", fallback + `  script:
    - '[ "$CI_COMMIT_REF_PROTECTED" = "true" ] && docker push "$CI_REGISTRY_IMAGE:latest"'
`, 0},
		{"else branch of a negated test", fallback + `  script:
    - if [ "$CI_COMMIT_BRANCH" != "main" ]; then echo skip; else docker push "$CI_REGISTRY_IMAGE:latest"; fi
`, 0},
		{"early exit off main", fallback + `  script:
    - if [ "$CI_COMMIT_BRANCH" != "$CI_DEFAULT_BRANCH" ]; then exit 0; fi
    - docker push "$CI_REGISTRY_IMAGE:latest"
`, 0},
		{"early exit with ||", fallback + `  script:
    - '[ -n "$CI_COMMIT_TAG" ] || exit 0'
    - npm publish
`, 0},
		{"target chosen in the shell", fallback + `  variables:
    BRANCH_IMAGE: $CI_REGISTRY_IMAGE/build-$CI_COMMIT_REF_SLUG
  script:
    - if [ -n "$CI_COMMIT_TAG" ]; then TARGET=$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG; else TARGET=$BRANCH_IMAGE; fi
    - docker push "$TARGET"
`, 0},
		// Still reported.
		{"latest push outside the if", fallback + `  script:
    - if [ "$CI_COMMIT_BRANCH" = "main" ]; then echo main; fi
    - docker push "$CI_REGISTRY_IMAGE:latest"
`, 1},
		{"if on an unprotected condition", fallback + `  script:
    - if [ "$PUSH" = "yes" ]; then docker push "$CI_REGISTRY_IMAGE:latest"; fi
`, 1},
		{"if on a branch pattern", fallback + `  script:
    - if [[ "$CI_COMMIT_BRANCH" == release* ]]; then docker push "$CI_REGISTRY_IMAGE:latest"; fi
`, 1},
		{"else branch of a positive test", fallback + `  script:
    - if [ "$CI_COMMIT_BRANCH" = "main" ]; then echo main; else docker push "$CI_REGISTRY_IMAGE:latest"; fi
`, 1},
		{"exit only in after_script", fallback + `  script:
    - docker push "$CI_REGISTRY_IMAGE:latest"
  after_script:
    - if [ "$CI_COMMIT_BRANCH" != main ]; then exit 0; fi
`, 1},
		{"push before the exit guard on the same line", fallback + `  script:
    - |
      docker push "$CI_REGISTRY_IMAGE:latest"
      if [ "$CI_COMMIT_BRANCH" != "main" ]; then exit 0; fi
`, 1},
		{"elif branch", fallback + `  script:
    - if [ -n "$CI_COMMIT_TAG" ]; then echo tag; elif [ -f x ]; then docker push "$CI_REGISTRY_IMAGE:latest"; fi
`, 1},
		{"nested if in the else branch", fallback + `  script:
    - if [ "$CI_COMMIT_BRANCH" != main ]; then if [ -f x ]; then echo; else docker push "$CI_REGISTRY_IMAGE:latest"; fi; fi
`, 1},
		{"unquoted -n", fallback + `  script:
    - if [ -n $CI_COMMIT_TAG ]; then docker push "$CI_REGISTRY_IMAGE:latest"; fi
`, 1},
		{"commented exit guard", fallback + `  script:
    - '# if [ "$CI_COMMIT_BRANCH" != "main" ]; then exit 0; fi'
    - docker push "$CI_REGISTRY_IMAGE:latest"
`, 1},
		{"default value assigned first", fallback + `  script:
    - TAG=latest
    - if [ -f sha ]; then TAG=$CI_COMMIT_SHA; fi
    - docker push "$CI_REGISTRY_IMAGE:$TAG"
`, 1},
		{"podman push to a fixed destination", fallback + `  script:
    - podman push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA $CI_REGISTRY_IMAGE:latest
`, 1},
		{"podman push between per-run refs", fallback + `  script:
    - podman push localhost/app:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
`, 0},
		{"exit guard inside after_script", fallback + `  script:
    - echo build
  after_script:
    - if [ "$CI_COMMIT_BRANCH" != main ]; then exit 0; fi
    - docker push "$CI_REGISTRY_IMAGE:latest"
`, 1},
		{"exit guard that keeps main out", fallback + `  script:
    - if [ "$CI_COMMIT_BRANCH" = main ]; then exit 0; fi
    - docker push "$CI_REGISTRY_IMAGE:latest"
`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y := "ship:\n  stage: build\n" + tc.job
			if f := findings080(t, y); len(f) != tc.want {
				t.Errorf("got %d findings, want %d: %v\n%s", len(f), tc.want, f, y)
			}
		})
	}
}

// #1524: a flag only protected rules: entries set, a per-run chart version,
// a test script with deploy in its name and a PowerShell message.
func TestGL080_Issue1524(t *testing.T) {
	flagRules := `  rules:
    - if: $CI_COMMIT_TAG
      variables: {PUSH_TAGS: "$CI_COMMIT_TAG latest"}
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      variables: {PUSH_TAGS: latest}
    - when: on_success
`
	push := `    - for t in $PUSH_TAGS; do docker push "$CI_REGISTRY_IMAGE:$t"; done
`
	helmRules := `  rules:
    - if: $CI_COMMIT_TAG
      variables: {HELM_VERSION: $CI_COMMIT_TAG}
    - when: on_success
      variables: {HELM_VERSION: 0.0.0-$CI_COMMIT_REF_SLUG}
`
	helmLogin := `    - helm repo add chart --username "$CI_REGISTRY_USER" --password "$CI_REGISTRY_PASSWORD" "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/helm/devel"
`
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"exit when the protected-only flag is empty", "push-image:\n" + flagRules + `  script:
    - '[ -n "$PUSH_TAGS" ] || exit 0'
` + push, 0},
		{"push in an if on the flag", "push-image:\n" + flagRules + `  script:
    - if [ "$PUSH_TAGS" != "" ]; then docker push "$CI_REGISTRY_IMAGE:latest"; fi
`, 0},
		{"flag compared to a value", "push-image:\n" + flagRules + `  script:
    - '[ "${PUSH_TAGS}" = latest ] && docker push "$CI_REGISTRY_IMAGE:latest"'
`, 0},
		{"fallback entry sets the flag too", "push-image:\n" + strings.Replace(flagRules, "    - when: on_success\n", "    - when: on_success\n      variables: {PUSH_TAGS: latest}\n", 1) + `  script:
    - '[ -n "$PUSH_TAGS" ] || exit 0'
` + push, 1},
		{"job variables set the flag", "push-image:\n  variables: {PUSH_TAGS: dev}\n" + flagRules + `  script:
    - '[ -n "$PUSH_TAGS" ] || exit 0'
` + push, 1},
		{"file variables set the flag", "variables: {PUSH_TAGS: dev}\npush-image:\n" + flagRules + `  script:
    - '[ -n "$PUSH_TAGS" ] || exit 0'
` + push, 1},
		{"an unprotected entry sets the flag", "push-image:\n" + strings.Replace(flagRules, "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", "$CI_COMMIT_BRANCH", 1) + `  script:
    - '[ -n "$PUSH_TAGS" ] || exit 0'
` + push, 1},
		{"the script assigns the flag", "push-image:\n" + flagRules + `  script:
    - export PUSH_TAGS=latest
    - '[ -n "$PUSH_TAGS" ] || exit 0'
` + push, 1},
		{"another job writes the flag to a dotenv report", "version:\n  script:\n    - echo \"PUSH_TAGS=latest\" >> build.env\n  artifacts: {reports: {dotenv: build.env}}\npush-image:\n" + flagRules + `  script:
    - '[ -n "$PUSH_TAGS" ] || exit 0'
` + push, 1},
		{"unquoted flag test", "push-image:\n" + flagRules + `  script:
    - '[ -n $PUSH_TAGS ] || exit 0'
` + push, 1},
		{"a never entry sets the flag", "push-image:\n" + strings.Replace(flagRules, "  rules:\n", "  rules:\n    - if: $CI_PIPELINE_SOURCE == \"schedule\"\n      when: never\n      variables: {PUSH_TAGS: latest}\n", 1) + `  script:
    - '[ -n "$PUSH_TAGS" ] || exit 0'
` + push, 0},
		{"per-run chart version through rules:variables", "publish:\n  stage: publish\n" + helmRules + `  script:
` + helmLogin + `    - helm package . --version="$HELM_VERSION"
    - helm cm-push chart-*.tgz chart
`, 0},
		{"per-run version on the push", "publish:\n  stage: publish\n  script:\n" + helmLogin + `    - helm cm-push . chart --version 0.0.0-$CI_COMMIT_SHORT_SHA
`, 0},
		{"chart version from Chart.yaml", "publish:\n  stage: publish\n  script:\n" + helmLogin + `    - helm package .
    - helm cm-push chart-*.tgz chart
`, 1},
		{"fixed chart version", "publish:\n  stage: publish\n  script:\n" + helmLogin + `    - helm package . --version 1.2.0
    - helm push chart-1.2.0.tgz oci://registry.example.com/charts
`, 1},
		{"chart packaged in another job", "publish:\n  stage: publish\n  script:\n" + helmLogin + `    - helm cm-push chart-*.tgz chart
`, 1},
		{"chart directory without a version", "publish:\n  stage: publish\n  script:\n" + helmLogin + `    - helm cm-push . chart
`, 1},
		{"per-run chart with a project secret", "publish:\n  stage: publish\n" + helmRules + `  script:
    - helm repo add chart --username bot --password "$CHART_REPO_PASSWORD" https://charts.example.com
    - helm package . --version="$HELM_VERSION"
    - helm cm-push chart-*.tgz chart
`, 1},
		{"per-run image with only the job's registry token", `publish:
  stage: publish
  script:
    - docker login -u "$CI_REGISTRY_USER" -p "$CI_REGISTRY_PASSWORD" "$CI_REGISTRY"
    - docker push "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
`, 0},
		{"job token without a readable publish", `publish:
  stage: publish
  script:
    - ./scripts/upload "$CI_JOB_TOKEN"
`, 1},
		{"test script with deploy in its name", `image-tags:
  stage: check
  script:
    - jobs/deploy-image-test
`, 0},
		{"deploy script", `image-tags:
  stage: check
  script:
    - ./deploy-staging.sh
`, 1},
		{"deploy script run by bash", `image-tags:
  stage: check
  script:
    - bash scripts/deploy.sh
`, 1},
		{"PowerShell message", `build-windows:
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - changes: ["*.cpp"]
  script:
    - Write-Output "Will run deploy command"
    - Write-Host "publish next"
`, 0},
		{"PowerShell message then a push", `build-windows:
  script:
    - Write-Output deploying; docker push "$CI_REGISTRY_IMAGE:latest"
`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings080(t, tc.yaml); len(f) != tc.want {
				t.Errorf("got %d findings, want %d: %v\n%s", len(f), tc.want, f, tc.yaml)
			}
		})
	}
}

func TestGL080_RulesVariablesEnvironment(t *testing.T) {
	review := `
render:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      variables: {ENV_NAME: production}
    - variables: {ENV_NAME: review/$CI_COMMIT_REF_SLUG}
  environment:
    name: $ENV_NAME
  script: [./render.sh]
`
	if f := findings080(t, review); len(f) != 0 {
		t.Errorf("per-branch environment from the fallback's variables: got %v, want none", f)
	}
	shared := `
deploy:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      variables: {ENV_NAME: live}
    - when: manual
      variables: {ENV_NAME: shared}
  environment:
    name: $ENV_NAME
  script: [./ship.sh]
`
	if f := findings080(t, shared); len(f) != 1 {
		t.Errorf("fixed environment from the fallback's variables: got %d findings, want 1", len(f))
	}
	jobVar := `
render:
  variables:
    ENV_NAME: review/$CI_COMMIT_REF_SLUG
  environment:
    name: $ENV_NAME
  script: [./render.sh]
`
	if f := findings080(t, jobVar); len(f) != 0 {
		t.Errorf("per-branch environment from job variables: got %v, want none", f)
	}
}

func TestGL080_ServiceContainerPublish(t *testing.T) {
	seed := `
seed:
  services:
    - name: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
      alias: app
  script:
    - tool config set remote http://app:9999
    - tool block publish 'blocks/*'
`
	if f := findings080(t, seed); len(f) != 0 {
		t.Errorf("publish to a service container: got %v, want none", f)
	}
	remote := `
seed:
  services:
    - name: postgres:16
  script:
    - tool config set remote https://registry.example.com
    - tool block publish 'blocks/*'
`
	if f := findings080(t, remote); len(f) != 1 {
		t.Errorf("publish to a remote host: got %d findings, want 1", len(f))
	}
	localhostHealth := `
publish:
  services: [postgres:16]
  script:
    - curl http://localhost:8080/health
    - mvn deploy -s settings.xml
`
	if f := findings080(t, localhostHealth); len(f) != 1 {
		t.Errorf("a health check on localhost next to mvn deploy: got %d findings, want 1", len(f))
	}
	push := `
seed:
  services: [docker:dind]
  script:
    - curl http://docker:2375/_ping
    - docker push $CI_REGISTRY_IMAGE:latest
`
	if f := findings080(t, push); len(f) != 1 {
		t.Errorf("registry push next to a service: got %d findings, want 1", len(f))
	}
}

// A deploy word in a directory name is no command, and a grep test of the
// tag's format that exits on every other ref guards the rest (#1527).
func TestGL080_Issue1527(t *testing.T) {
	cred := "  variables:\n    NPM_TOKEN: $NPM_TOKEN\n"
	push := "    - docker login -u u -p \"$REG_PASSWORD\" registry.example.com\n    - docker push registry.example.com/x:$CI_COMMIT_TAG\n"
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"cd into a Deploy directory", "t:\n" + cred + "  script:\n    - cd \"desafio/Deploy de uma app\"\n    - npm test\n", 0},
		{"pushd into deploy", "t:\n" + cred + "  script:\n    - pushd deploy/tests && npm test\n", 0},
		{"cd then a deploy script", "t:\n" + cred + "  script:\n    - cd deploy && ./deploy.sh\n", 1},
		{"cd then a real push", "t:\n  script:\n    - cd deploy\n    - docker push registry.example.com/x:latest\n", 1},
		{"grep -v exit guard", "pub:\n  script:\n    - if echo \"$CI_COMMIT_TAG\" | grep -vqE '^[0-9]+\\.[0-9]+\\.[0-9]+$'; then exit 1; fi\n" + push, 0},
		{"grep -vqEo as found", "pub:\n  script:\n    - if echo \"$CI_COMMIT_TAG\" | grep -vqEo '^v?[0-9]+\\.[0-9]+'; then exit 1; fi\n" + push, 0},
		{"grep || exit", "pub:\n  script:\n    - echo \"$CI_COMMIT_TAG\" | grep -qE '^v[0-9]+' || exit 0\n" + push, 0},
		{"negated grep exit", "pub:\n  script:\n    - if ! echo \"$CI_COMMIT_TAG\" | grep -qE '^v[0-9]+'; then exit 0; fi\n" + push, 0},
		{"push in grep if", "pub:\n  script:\n    - if echo \"${CI_COMMIT_TAG}\" | grep -q '^v[0-9]'; then docker push registry.example.com/x:latest; fi\n", 0},
		{"pattern matches empty", "pub:\n  script:\n    - if echo \"$CI_COMMIT_TAG\" | grep -vqE '^[0-9]*$'; then exit 1; fi\n" + push, 1},
		{"grep without -v exits on tags", "pub:\n  script:\n    - if echo \"$CI_COMMIT_TAG\" | grep -qE '^v[0-9]+'; then exit 1; fi\n" + push, 1},
		{"grep on the branch", "pub:\n  script:\n    - if echo \"$CI_COMMIT_BRANCH\" | grep -vq '^main$'; then exit 0; fi\n" + push, 1},
		{"variable in the pattern", "pub:\n  script:\n    - if echo \"$CI_COMMIT_TAG\" | grep -vqE \"^$PREFIX[0-9]+\"; then exit 1; fi\n" + push, 1},
		{"unknown grep flag", "pub:\n  script:\n    - if echo \"$CI_COMMIT_TAG\" | grep -vqF '1.0'; then exit 1; fi\n" + push, 1},
		{"echo -n gives grep no line", "pub:\n  script:\n    - if echo -n \"$CI_COMMIT_TAG\" | grep -vqE '^v'; then exit 1; fi\n" + push, 1},
		{"guard after the push", "pub:\n  script:\n" + push + "    - if echo \"$CI_COMMIT_TAG\" | grep -vqE '^v'; then exit 1; fi\n", 1},
		{"grep guard in a subshell", "pub:\n  script:\n    - (echo \"$CI_COMMIT_TAG\" | grep -qE '^v' || exit 0)\n" + push, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings080(t, tc.yaml); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %+v", tc.want, f)
			}
		})
	}
}

func TestGrepRefTest(t *testing.T) {
	for cond, want := range map[string]int{
		`echo "$CI_COMMIT_TAG" | grep -vqE '^v[0-9]'`:   -1,
		`echo "$CI_COMMIT_TAG" | grep -qE '^v[0-9]'`:    1,
		`echo $CI_COMMIT_TAG | grep -q -e 'v'`:          1,
		`echo "$CI_COMMIT_TAG" | grep -qix 'v1'`:        1,
		`echo "$CI_COMMIT_TAG" | grep -vqE '^(v[0-9]'`:  0,
		`echo "$CI_COMMIT_TAG | grep -q 'v'`:            0,
		`echo "$PUSH" | grep -q 'v'`:                    1,
		`echo "$OTHER" | grep -q 'v'`:                   0,
		`echo "$CI_COMMIT_TAG" | grep -q "^v[0-9]+$"`:   1,
		`echo "$CI_COMMIT_TAG" | grep -v -v -q '^v'`:    1,
		`echo "$CI_COMMIT_TAG" | grep -qE '^v' | wc -l`: 0,
	} {
		if got := refTest(cond, map[string]bool{"PUSH": true}); got != want {
			t.Errorf("refTest(%q) = %d, want %d", cond, got, want)
		}
	}
}

func TestGL080_Issue1538(t *testing.T) {
	up := func(url string) string {
		return "pub:\n  script:\n    - 'curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" --upload-file x.tgz \"" + url + "\"'\n"
	}
	api := "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/"
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"fixed version", up(api + "x/1.0.0/x.tgz"), 1},
		{"version from a variable", "variables:\n  V: 1.0.0\n" + up(api+"x/$V/x.tgz"), 1},
		{"tag version", up(api + "x/$CI_COMMIT_TAG/x.tgz"), 1},
		{"per-branch version", up(api + "x/${CI_COMMIT_REF_SLUG}/x.tgz"), 0},
		{"per-commit file", up(api + "x/1.0/x-$CI_COMMIT_SHORT_SHA.tgz"), 0},
		{"per-run through variables", "variables:\n  V: 0.0.0-$CI_PIPELINE_IID\n" + up(api+"x/$V/x.tgz"), 0},
		{"multi-line upload", "pub:\n  script:\n    - |\n      curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" \\\n        --upload-file x.tgz \\\n        \"" + api + "x/1.0.0/x.tgz\"\n", 1},
		{"download", "pub:\n  script:\n    - curl -o x.tgz \"" + api + "x/1.0.0/x.tgz\"\n", 0},
		{"upload elsewhere", "pub:\n  script:\n    - curl --upload-file report.xml https://hooks.example.com/r\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings080(t, tc.yaml); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %+v", tc.want, f)
			}
		})
	}
}

func TestGL080_Issue1546(t *testing.T) {
	wf := "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n"
	cred := "  variables:\n    TOKEN: $DEPLOY_TOKEN\n"
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"make target starting with deploy", wf + "info:\n" + cred + "  script:\n    - make deployment-info\n", 0},
		{"make xray-publish", wf + "t:\n" + cred + "  script:\n    - make test\n  after_script:\n    - make xray-publish\n", 0},
		{"make deploy stays", wf + "d:\n" + cred + "  script:\n    - make deploy\n", 1},
		{"make deploy-prod stays", wf + "d:\n" + cred + "  script:\n    - make deploy-prod\n", 1},
		{"pre-deploy stage", wf + "pack:\n  stage: pre-deploy\n  script:\n    - npm config set //reg/:_auth $NEXUS_NPM_PASS\n    - npm pack\n", 0},
		{"deploy stage stays", wf + "pack:\n  stage: deploy\n  script:\n    - npm config set //reg/:_auth $NEXUS_NPM_PASS\n    - npm pack\n", 1},
		{"make deploy into kind", wf + "e2e:\n" + cred + "  before_script:\n    - kind create cluster\n  script:\n    - make deploy verify undeploy\n", 0},
		{"make deploy without local cluster", wf + "e2e:\n" + cred + "  script:\n    - make deploy verify undeploy\n", 1},
		{"semantic-release-cargo version", wf + "lint:\n" + cred + "  before_script:\n    - semantic-release-cargo --version\n  script:\n    - cargo clippy\n", 0},
		{"semantic-release stays", wf + "rel:\n  script:\n    - npx semantic-release\n", 1},
		{"workflow rules tag per branch", "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n      variables: {TAG: latest}\n    - if: $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH\n      variables: {TAG: $CI_COMMIT_REF_SLUG}\nb:\n  script:\n    - docker push $CI_REGISTRY_IMAGE:$TAG\n", 0},
		{"workflow rules fixed tag stays", "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n      variables: {TAG: latest}\n    - if: $CI_COMMIT_BRANCH\n      variables: {TAG: edge}\nb:\n  script:\n    - docker push $CI_REGISTRY_IMAGE:$TAG\n", 1},
		{"rules tag with fixed default stays", "variables:\n  TAG: latest\nworkflow:\n  rules:\n    - if: $CI_MERGE_REQUEST_IID\n      variables: {TAG: $CI_COMMIT_REF_SLUG}\n    - if: $CI_COMMIT_BRANCH\nb:\n  script:\n    - docker push $CI_REGISTRY_IMAGE:$TAG\n", 1},
		{"git describe version", wf + "up:\n  script:\n    - v=$(git describe --always --tags HEAD)\n    - 'curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" --upload-file f \"$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/pkg/${v}/f\"'\n", 0},
		{"git describe abbrev 0 stays", wf + "up:\n  script:\n    - v=$(git describe --tags --abbrev=0)\n    - 'curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" --upload-file f \"$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/pkg/${v}/f\"'\n", 1},
		{"scp to per-pipeline dir", wf + "rootfs:\n  script:\n    - scp -P 2222 out.tar.xz ci@host:/srv/cache/${CI_PIPELINE_ID}/\n", 0},
		{"scp to fixed dir stays", wf + "rootfs:\n  script:\n    - scp out.tar.xz ci@host:/srv/www/\n", 1},
		{"rsync to variable dest stays", wf + "pub:\n  script:\n    - rsync -a repo/ $DEST/\n", 1},
		{"fdroid publish", wf + "p:\n" + cred + "  script:\n    - fdroid publish --verbose\n", 0},
		{"fdroid deploy stays", wf + "p:\n" + cred + "  script:\n    - fdroid deploy\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings080(t, tc.yaml); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %+v", tc.want, f)
			}
		})
	}
}

// A job whose rules: are all when: never never runs (#1548), as when a root
// file switches off an included job.
func TestGL080_RulesOnlyWhenNever(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"never only", "d:\n  environment: production-eu\n  script: [docker push img:latest]\n  rules:\n    - when: never\n", 0},
		{"anchor override", "x: &never\n  rules:\n    - when: never\nd:\n  <<: *never\n  script: [docker push img:latest]\n", 0},
		{"manual only", "d:\n  script: [docker push img:latest]\n  rules:\n    - when: manual\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings080(t, tc.yaml); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %+v", tc.want, f)
			}
		})
	}
}

// Script shapes the per-run and dry-run exceptions didn't read (#1550).
func TestGL080_Issue1550(t *testing.T) {
	api := "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/app"
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"time before a per-ref upload", "b:\n  script:\n    - 'time curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" --upload-file a.iso \"" + api + "/${CI_COMMIT_TAG:-$CI_COMMIT_BRANCH}/a.iso\"'\n", 0},
		{"sudo before a fixed upload stays", "b:\n  script:\n    - 'sudo -E curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" --upload-file a.iso \"" + api + "/1.0/a.iso\"'\n", 1},
		{"continued dry run", "r:\n  script:\n    - |\n      npx \\\n        -p semantic-release@21 \\\n        semantic-release --no-ci --dry-run 2>&1 | tee semantic-release.log || true\n      cat semantic-release.log\n", 0},
		{"snapshot through substitution", "release:\n  script:\n    - goreleaser release --clean $([ -z ${CI_COMMIT_TAG} ] && echo \"--snapshot\")\n", 0},
		{"goreleaser without snapshot stays", "release:\n  script:\n    - goreleaser release --clean\n", 1},
		{"push with a substitution flag", "b:\n  script:\n    - export IMAGE=\"reg.example.com/app:${CI_COMMIT_TAG:-\"$CI_COMMIT_SHORT_SHA\"}-jvm\"\n    - 'docker push --platform=linux/\"$(uname -m | grep -qxF aarch64 && printf arm64 || printf amd64)\" \"$IMAGE\"'\n", 0},
		{"fixed push with a substitution flag stays", "b:\n  script:\n    - 'docker push --platform=linux/\"$(uname -m | grep -qxF aarch64 && printf arm64 || printf amd64)\" reg.example.com/app:latest'\n", 1},
		{"variable rewritten from itself", "variables:\n  IMG: \"${CI_COMMIT_BRANCH}${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME}\"\nb:\n  script:\n    - IMG=$(echo \"$IMG\" | tr A-Z a-z)\n    - docker push reg.example.com/app/$IMG:svc\n", 0},
		{"fixed variable rewritten from itself stays", "variables:\n  IMG: app\nb:\n  script:\n    - IMG=$(echo \"$IMG\" | tr A-Z a-z)\n    - docker push reg.example.com/$IMG:latest\n", 1},
		{"loop over per-run tags", "b:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n      variables: {EXTRA_TAGS: latest}\n    - when: on_success\n  script:\n    - ALL_TAGS=\"$CI_COMMIT_SHA $EXTRA_TAGS\"\n    - 'for tag in $ALL_TAGS; do crane push img.tar \"$CI_REGISTRY_IMAGE:$tag\"; done'\n", 0},
		{"loop with a fixed tag stays", "b:\n  script:\n    - 'for tag in $CI_COMMIT_SHA latest; do crane push img.tar \"$CI_REGISTRY_IMAGE:$tag\"; done'\n", 1},
		{"exit in a brace group", "b:\n  rules:\n    - if: $CI_COMMIT_BRANCH == \"master\"\n      variables: {PUSH_TAGS: latest}\n    - when: on_success\n  script:\n    - '[ -n \"$PUSH_TAGS\" ] || { echo skip; exit 0; }'\n    - docker push $CI_REGISTRY_IMAGE:$PUSH_TAGS\n", 0},
		{"brace group without exit stays", "b:\n  rules:\n    - if: $CI_COMMIT_BRANCH == \"master\"\n      variables: {PUSH_TAGS: latest}\n    - when: on_success\n  script:\n    - '[ -n \"$PUSH_TAGS\" ] || { echo skip; }'\n    - docker push $CI_REGISTRY_IMAGE:latest\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings080(t, tc.yaml); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %+v", tc.want, f)
			}
		})
	}
}

func TestJobProtectedOnlyOnlyMapping(t *testing.T) {
	for src, want := range map[string]bool{
		"only:\n  refs: [main, tags]\n":                                   true,
		"only:\n  refs: [main, feature]\n":                                false,
		"only:\n  variables: [$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH]\n": true,
		"only:\n  variables: [$CI_COMMIT_BRANCH == \"main\", $DEPLOY]\n":  false,
		"only:\n  variables: [{x: y}]\n":                                  false,
		"only:\n  refs: [feature]\n  variables: [$CI_COMMIT_TAG]\n":       true,
		"only:\n  changes: [a/**]\n":                                      false,
		"only:\n  refs: []\n":                                             false,
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(src), &n); err != nil {
			t.Fatal(err)
		}
		if got := jobProtectedOnly(parser.Unwrap(&n)); got != want {
			t.Errorf("jobProtectedOnly(%q) = %v, want %v", src, got, want)
		}
	}
}

func TestGL080ScriptHelpers(t *testing.T) {
	var vars yaml.Node
	if err := yaml.Unmarshal([]byte("A: from-job\n"), &vars); err != nil {
		t.Fatal(err)
	}
	var global yaml.Node
	if err := yaml.Unmarshal([]byte("B: from-file\nL: \"x y\"\n"), &global); err != nil {
		t.Fatal(err)
	}
	jv, gv := parser.Unwrap(&vars), parser.Unwrap(&global)
	sv := map[string][]string{"C": {"one", "two"}, "E": {""}, "F": nil}
	for name, want := range map[string]string{"A": "from-job", "B": "from-file", "C": "two", "D": "", "F": ""} {
		if got := previousValue(name, sv, jv, gv); got != want {
			t.Errorf("previousValue(%s) = %q, want %q", name, got, want)
		}
	}
	if got := strings.Join(loopWords(`$L "$C" $E`, sv, jv, gv), ","); got != "x,y,two" {
		t.Errorf("loopWords = %q", got)
	}
	for in, want := range map[string]string{
		"docker push --platform=linux/\"$(uname -m | tr a b)\" img": "docker push --platform=linux/\"$__subst\" img",
		"docker push `cat name`":                                    "docker push $__subst",
		"echo $(docker push img:latest)":                            "echo $(docker push img:latest)",
		"echo $((1+2)) and `unclosed":                               "echo $((1+2)) and `unclosed",
		"x $(unclosed":                                              "x $(unclosed",
		"plain":                                                     "plain",
	} {
		if got := collapseSubstitutions(in); got != want {
			t.Errorf("collapseSubstitutions(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]bool{
		"crane push img.tar reg/x:$CI_COMMIT_SHA": true,
		"crane push img.tar reg/x:latest":         false,
		"crane copy a b":                          false,
		"crane push":                              false,
	} {
		if got := ephemeralImagePush(strings.Fields(in), nil, nil, nil); got != want {
			t.Errorf("ephemeralImagePush(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestGL080_Issue1552(t *testing.T) {
	noMR := "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n"
	remote := "include:\n  - project: g/templates\n    file: docker.yml\n"
	for _, tc := range []struct {
		name, yaml string
		want       finding.Severity
		msg        string
	}{
		{"build-label environment", "build:\n  environment: build\n  script: [tox -e build]\n", finding.Info, ""},
		{"build-label environment with a push", "build:\n  environment: build\n  script: [docker push reg.example.com/app:latest]\n", finding.Warn, ""},
		{"deploy environment", "d:\n  environment: eu-central\n  script: [tox -e build]\n", finding.Warn, ""},
		{"unread target with an unread include", remote + "b:\n  script: [docker push $TMP_IMAGE]\n", finding.Info, ""},
		{"unread tag with an unread include", remote + "b:\n  script: [docker push reg.example.com/app:$VERSION]\n", finding.Info, ""},
		{"fixed tag under an unread namespace", remote + "b:\n  script: ['docker push \"$REGISTRY_USER\"/app:stable']\n", finding.Warn, ""},
		{"unread package version", remote + "b:\n  script:\n    - 'curl --header \"JOB-TOKEN: $CI_JOB_TOKEN\" --upload-file f \"$CI_API_V4_URL/projects/1/packages/generic/p/$GitVersion/f\"'\n", finding.Info, ""},
		{"tag from the job's variables", remote + "b:\n  variables:\n    TAG: stable\n  script: [docker push reg.example.com/app:$TAG]\n", finding.Warn, ""},
		{"tag from the script", remote + "b:\n  script:\n    - TAG=stable\n    - docker push reg.example.com/app:$TAG\n", finding.Warn, ""},
		{"tag from a CI variable", remote + "b:\n  script: [docker push reg.example.com/app:$CI_DEFAULT_BRANCH]\n", finding.Warn, ""},
		{"fallback entry with MR pipelines", "d:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: manual\n  script: [docker push reg.example.com/app:latest]\n", finding.Warn, "fork's merge request"},
		{"fallback entry without MR pipelines", noMR + "d:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: manual\n  script: [docker push reg.example.com/app:latest]\n", finding.Warn, "any branch can run it;"},
		{"unread target without include", "b:\n  script: [docker push $TMP_IMAGE]\n", finding.Warn, ""},
		{"known target with an unread include", remote + "variables:\n  IMG: reg.example.com/app:latest\nb:\n  script: [docker push $IMG]\n", finding.Warn, ""},
		{"matrix target with an unread include", remote + "b:\n  parallel:\n    matrix:\n      - IMG: [a, b]\n  script: [docker push reg.example.com/$IMG:latest]\n", finding.Warn, ""},
		{"API delete with own token", "publish_package:\n  script:\n    - 'curl --request DELETE --header \"PRIVATE-TOKEN: $GITLAB_RELEASE_TOKEN\" \"$CI_API_V4_URL/projects/$CI_PROJECT_ID/repository/tags/v1\"'\n", finding.Info, ""},
		{"API post with bearer", "t:\n  script:\n    - 'curl -X POST -H \"Authorization: Bearer ${API_TOKEN}\" https://gitlab.example.com/api/v4/projects/1/releases'\n", finding.Info, ""},
		{"fork wording with MR pipelines", "d:\n  script: [docker push reg.example.com/app:latest]\n", finding.Warn, "fork merge requests"},
		{"branch wording without MR pipelines", noMR + "d:\n  script: [docker push reg.example.com/app:latest]\n", finding.Warn, "runs on every branch"},
		{"manual wording without MR pipelines", noMR + "d:\n  when: manual\n  script: [docker push reg.example.com/app:latest]\n", finding.Warn, "anyone who can push a branch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings080(t, tc.yaml)
			if len(f) != 1 || f[0].Severity != tc.want || !strings.Contains(f[0].Message, tc.msg) {
				t.Fatalf("want one %s finding with %q, got %+v", tc.want, tc.msg, f)
			}
		})
	}
	for name, y := range map[string]string{ //nolint:gosec // G101: test fixtures name variables, no secrets
		"API read with own token":   "t:\n  script:\n    - 'curl --header \"PRIVATE-TOKEN: $TOKEN\" \"$CI_API_V4_URL/projects/1/releases\"'\n",
		"API write with job token":  "t:\n  script:\n    - 'curl --request POST --header \"JOB-TOKEN: $CI_JOB_TOKEN\" \"$CI_API_V4_URL/projects/1/releases\"'\n",
		"API write with CI_ header": "t:\n  script:\n    - 'curl -X PUT --header \"PRIVATE-TOKEN: $CI_JOB_TOKEN\" \"$CI_API_V4_URL/projects/1\"'\n",
		"write to another API":      "t:\n  script:\n    - 'curl -X POST -H \"Authorization: Bearer $T\" https://api.example.com/v1/x'\n",
	} {
		if f := findings080(t, y); len(f) != 0 {
			t.Errorf("%s: want no finding, got %+v", name, f)
		}
	}
	for _, src := range []string{"parallel: 3\n", "parallel:\n  matrix: x\n", "parallel:\n  matrix: [x]\n"} {
		var mr yaml.Node
		if err := yaml.Unmarshal([]byte(src), &mr); err != nil {
			t.Fatal(err)
		}
		if matrixVariable(parser.Unwrap(&mr), "X") {
			t.Errorf("matrixVariable(%q)", src)
		}
	}
	for src, want := range map[string]bool{
		"include: https://example.com/ci.yml\n": true,
		"include:\n  - local: a.yml\n":          false,
		"include:\n  - template: Jobs/x.yml\n":  true,
		"include: a.yml\n":                      false,
		"x: 1\n":                                false,
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(src), &n); err != nil {
			t.Fatal(err)
		}
		if got := hasUnreadInclude(parser.Unwrap(&n)); got != want {
			t.Errorf("hasUnreadInclude(%q) = %v, want %v", src, got, want)
		}
	}
}
