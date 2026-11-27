// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func TestGL017_DeployScriptCommandsOnly(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    int
	}{
		{`echo "Do your deploy here"`, 0},
		{`printf 'publish step\n'`, 0},
		{`echo deploy`, 0},
		{`echo 'publish here' && echo deploy`, 0},
		{`echo deploy && ./deploy.sh`, 1},
		{`./deploy.sh`, 1},
		{`make deploy`, 1},
		{`npm run deploy`, 1},
		{`deploy --prod`, 1},
		{`twine upload dist/*`, 1},
		{`bash "$CI_PROJECT_DIR/scripts/deploy.sh"`, 1},
		{`ssh deploy@host "cd /app && ./deploy.sh"`, 1},
		{`curl -X POST "https://api.example.com/v1/deploy"`, 1},
		{`echo 'kubectl apply -f k8s/'`, 0},
		{`printf 'kubectl apply -f k8s/'`, 0},
		{`echo 'kubectl apply -f k8s/' | ssh user@host bash`, 1},
		{`printf 'kubectl apply -f k8s/' | ssh user@host bash`, 1},
		{`ssh user@host bash -s <<EOF
kubectl apply -f k8s/
EOF`, 1},
		{`ansible-playbook -i hosts site.yml --syntax-check`, 0},
		{`ansible-playbook site.yml --list-tasks`, 0},
		{`ansible-playbook site.yml --list-hosts`, 0},
		{`ansible-playbook -i hosts site.yml`, 1},
		{`ansible-playbook -i hosts site.yml --check`, 1},
		{`fastlane test`, 0},
		{`fastlane ios test`, 0},
		{`fastlane update_fastlane`, 0},
		{`fastlane scan`, 0},
		{`fastlane playstore`, 1},
		{`fastlane deliver`, 1},
		{`fastlane ios release`, 1},
		{`fastlane ios`, 1},
		{`bundle exec fastlane test`, 0},
		{`bundle exec fastlane tests`, 0},
		{`bundler exec fastlane build`, 0},
		{`bundle exec fastlane ios test`, 0},
		{`bundle _2.4.1_ exec fastlane scan`, 0},
		{`bundle exec fastlane deliver`, 1},
		{`bundle exec fastlane ios release`, 1},
		{`apt-get install -y rsync`, 0},
		{`apk add --no-cache openssh-client rsync`, 0},
		{`pip install ansible`, 0},
		{`gem install fastlane`, 0},
		{`npm install -g vercel`, 0},
		{`yarn add netlify-cli`, 0},
		{`rsync -av ./ user@host:/srv`, 1},
		{`apt-get install -y rsync && rsync -av ./ user@host:/srv`, 1},
	} {
		t.Run(tc.command, func(t *testing.T) {
			f := findings017(t, fmt.Sprintf("deploy-example:\n  stage: deploy\n  script:\n    - %s\n", strconv.Quote(tc.command)))
			if len(f) != tc.want {
				t.Fatalf("got %+v, want %d findings", f, tc.want)
			}
			if tc.want == 1 && (f[0].RuleID != "GL017" || f[0].Severity != finding.Warn) {
				t.Errorf("unexpected finding %+v", f[0])
			}
		})
	}
}

func findings017(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL017.Check(doc.Root, "test.yml")
}

func TestGL017_DeployNoTags(t *testing.T) {
	f := findings017(t, `
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

func TestGL017_EnvironmentNoTags(t *testing.T) {
	f := findings017(t, `
deploy:
  environment: production
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for environment job without tags, got %d", len(f))
	}
}

func TestGL017_DeployWithTags_NoFinding(t *testing.T) {
	f := findings017(t, `
deploy-prod:
  stage: deploy
  tags:
    - production
    - docker
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when tags are set, got %d", len(f))
	}
}

func TestGL017_EmptyTagsList(t *testing.T) {
	f := findings017(t, `
deploy-prod:
  stage: deploy
  tags: []
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for empty tags list, got %d", len(f))
	}
}

func TestGL017_BuildJobNoTags_NoFinding(t *testing.T) {
	f := findings017(t, `
build:
  stage: build
  script:
    - go build ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-deploy job without tags, got %d", len(f))
	}
}

func TestGL017_TestJobNoTags_NoFinding(t *testing.T) {
	f := findings017(t, `
unit-tests:
  stage: test
  script:
    - go test ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for test job without tags, got %d", len(f))
	}
}

func TestGL017_ReleaseStage(t *testing.T) {
	f := findings017(t, `
publish-pkg:
  stage: release
  script:
    - npm publish
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for release-stage job without tags, got %d", len(f))
	}
}

func TestGL017_PublishStage(t *testing.T) {
	f := findings017(t, `
publish-image:
  stage: publish
  script:
    - docker push $CI_REGISTRY_IMAGE
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for publish-stage job without tags, got %d", len(f))
	}
}

func TestGL017_MultipleJobs(t *testing.T) {
	f := findings017(t, `
build:
  stage: build
  script: [go build]

deploy-staging:
  stage: deploy
  script: [./deploy.sh staging]

deploy-prod:
  environment: production
  script: [./deploy.sh prod]
  tags:
    - prod-runner
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (deploy-staging has no tags), got %d", len(f))
	}
}

func TestGL017_LineNumber(t *testing.T) {
	f := findings017(t, `
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

func TestGL017_TriggerJob_NoFinding(t *testing.T) {
	f := findings017(t, `
start-release-pipeline:
  stage: deploy
  trigger:
    include: .gitlab/ci/release.yml
    strategy: depend
`)
	if len(f) != 0 {
		t.Fatalf("a trigger job runs on no runner, tags: doesn't apply; got %+v", f)
	}
}

func TestEnvActionNoDeploy(t *testing.T) {
	for action, want := range map[string]bool{
		"start":   false,
		"prepare": true,
		"stop":    true,
		"verify":  true,
		"access":  true,
	} {
		doc, err := parser.Parse([]byte("job:\n  environment:\n    name: production\n    action: "+action+"\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		job := parser.FindKey(parser.Unwrap(doc.Root), "job")
		env := parser.FindKey(job, "environment")
		if got := envActionNoDeploy(env); got != want {
			t.Errorf("%s: got %t, want %t", action, got, want)
		}
	}
}

func TestGL017_DevTierEnvironmentStillNeedsTags(t *testing.T) {
	f := findings017(t, `
review:
  environment:
    name: review/mr-$CI_MERGE_REQUEST_IID
    deployment_tier: development
  script:
    - ./preview.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected a review deploy to still need runner tags, got %+v", f)
	}
}

// TestLineDeploys covers the release false-positive scan of jobScriptDeploys:
// a deploy/publish verb in a comment, a path, a flag, a filename argument, a
// local dotnet publish, or a snapshot/skip-publish release is not a deployment,
// while a real deploy command, script, or webhook still is.
func TestLineDeploys(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{`./deploy.sh`, true},
		{`'.\CICD\publish_to_marketplace.ps1'`, true},
		{`.\CICD\publish_to_marketplace.ps1`, true},
		{`.\CICD\build.ps1`, false},
		{`jobs/deploy-image-test`, false},
		{`./scripts/publish_check.sh`, false},
		{`Write-Output "Will run deploy command"`, false},
		{`write-host "publish next"`, false},
		{`helm cm-push chart.tgz repo`, true},
		{`cd "desafio/Deploy de uma app"`, false},
		{`pushd deploy`, false},
		// curl uploads to the GitLab package registry (#1538).
		{`curl --fail --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file build/u-boot.bin "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/u-boot/${VERSION}/u-boot.bin"`, true},
		{`curl -H "JOB-TOKEN: $CI_JOB_TOKEN" "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/x/1.0/x.tgz" --upload-file x.tgz`, true},
		{`curl -sfT x.tgz https://gitlab.example.com/api/v4/projects/42/packages/generic/x/1.0/x.tgz`, true},
		{`curl -T x.zip ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/x/1/x.zip`, true},
		{`curl --upload-file report.xml https://hooks.example.com/upload`, false},
		{`curl -T coverage.json https://s3.example.com/scratch/coverage.json`, false},
		{`curl -o x.tgz "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/x/1.0/x.tgz"`, false},
		{`curl --header "JOB-TOKEN: $CI_JOB_TOKEN" "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/x/1.0/x.tgz" -o x.tgz; tar -xf x.tgz`, false},
		{`cd deploy && ./deploy.sh`, true},
		{`bash scripts/deploy-prod.sh`, true},
		{`make deploy`, true},
		{`npm run publish`, true},
		{`firebase deploy --only hosting`, true},
		{`helm upgrade app ./chart`, true},
		{`kubectl apply -f k8s/`, true},
		{`goreleaser release --clean`, true},
		{`curl -X POST https://ci.example.com/v1/deploy`, true},
		{`ssh deploy@host "./deploy.sh"`, true},
		{`make container-publish`, true},
		{`task xray-publish`, false}, // uploads test results to Jira Xray
		{`task docs-publish`, true},
		{`make deployment-info`, false},
		{`make deploy-status`, false},
		{`mage deployer:upload`, true},
		{`make get-deployed-charts`, false},
		{`bun -e "if (p.publishConfig) process.exit(1)"`, false},
		{`make -e deploy`, true},
		{`./tools/check-fastlane-whitespace.py`, false},
		{`bundle exec fastlane beta`, true},
		{`npx vercel --prod`, true},
		{`kubectl kustomize overlays/prod | kubectl apply -f -`, true},
		{`npm run deploy:prod`, true},
		{`fdroid publish --verbose`, false},
		{`fdroid deploy`, true},
		{`semantic-release-cargo --version`, false},
		{`npx semantic-release`, true},
		{`npm run build-and-deploy`, true},
		// Not deployments (the release FP scan classes):
		{`# build for deploy`, false},
		{`composer validate --no-check-publish`, false},
		{`docker-compose -f deploy/docker-compose.yml up`, false},
		{`emacs -batch -q -l publish.el -f org-publish`, false},
		{`goreleaser release --clean --snapshot`, false},
		{`$GORELEASER_IMAGE release --skip publish --snapshot`, false},
		{`python manage.py check --deploy --fail-level WARNING`, false},
		{`dotnet publish -c Release -o out`, false},
		{`pytest tests/deploy/test_foo.py`, false},
		{`golangci-lint run ./cmd/scp-wallet/...`, false},
		{`album deploy -h`, false},
		{`mytool publish --help`, false},
		{`pixi publish --target-dir pkg`, false},
		{`pixi publish --path .`, false},
		{`scp dist/app.tar.gz host:/srv/`, true},
		{`/usr/bin/rsync -av dist/ host:/srv/`, true},
		{`rsync -a ~/.cache home/`, false},
		{`cp -r a b && rsync -a build/ public/`, false},
		{`rsync -av -e ssh dist/ deploy@host.example:/srv/`, true},
		{`rsync -a dist/ $DEPLOY_TARGET`, true},
		{`rsync -a dist/ rsync://mirror.example/mod/`, true},
		{`rsync -a --delete dist/ /var/www/html/`, true},
		{`rsync --version`, false},
		{"rsync -a dist/ `cat .deploy-target`", true},
		{`pixi publish --to https://prefix.dev/my-channel`, true},
		{`pixi publish --target-channel=s3://bucket/channel`, true},
	} {
		t.Run(tc.line, func(t *testing.T) {
			if got := lineDeploys(tc.line); got != tc.want {
				t.Errorf("lineDeploys(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}
