// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// Keys a job inherits through extends: or default: count, hidden templates
// are not reported themselves, and a job extending a template from another
// file is skipped (#758).
func TestInheritedKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule string
		yaml string
		want int
	}{
		{"GL017 tags from default", "GL017", `
default:
  tags: [trusted]
deploy:
  stage: deploy
  script: [./deploy.sh]
`, 0},
		{"GL017 tags from extends", "GL017", `
.runner:
  tags: [trusted]
deploy:
  extends: .runner
  stage: deploy
  script: [./deploy.sh]
`, 0},
		{"GL017 inherit default false", "GL017", `
default:
  tags: [trusted]
deploy:
  inherit:
    default: false
  stage: deploy
  script: [./deploy.sh]
`, 1},
		{"GL017 environment from extends", "GL017", `
.prod:
  environment: production
deploy:
  extends: .prod
  script: [./deploy.sh]
`, 1},
		{"GL017 hidden template", "GL017", `
.deploy:
  stage: deploy
  script: [./deploy.sh]
`, 0},
		{"GL017 template in another file", "GL017", `
deploy:
  extends: .from-include
  stage: deploy
  script: [./deploy.sh]
`, 0},
		{"GL019 resource_group from extends", "GL019", `
.base:
  resource_group: prod
deploy:
  extends: [.other, .base]
  stage: deploy
  script: [./deploy.sh]
.other:
  image: alpine:3.20.3
`, 0},
		{"GL019 hidden template", "GL019", `
.deploy_template: &deploy
  stage: deploy
  script: [./deploy.sh]
`, 0},
		{"GL019 still reported", "GL019", `
deploy:
  stage: deploy
  script: [./deploy.sh]
`, 1},
		{"GL005 expire_in from extends", "GL005", `
.build:
  artifacts:
    expire_in: 1 week
editor:
  extends: .build
  artifacts:
    paths: [build/]
  script: [make]
`, 0},
		{"GL005 artifacts only in template", "GL005", `
.build:
  artifacts:
    paths: [build/]
editor:
  extends: .build
  script: [make]
`, 1},
		{"GL005 hidden template alone", "GL005", `
.build:
  artifacts:
    paths: [build/]
`, 0},
		{"GL005 path in a template still checked", "GL005", `
.build:
  artifacts:
    expire_in: 1 week
    paths: [.env]
`, 1},
		{"GL034 strategy from extends", "GL034", `
.pipeline:
  trigger:
    project: group/other
    strategy: depend
child:
  extends: .pipeline
  trigger:
    branch: main
`, 0},
		{"GL034 no strategy anywhere", "GL034", `
.pipeline:
  trigger:
    project: group/other
child:
  extends: .pipeline
  trigger:
    branch: main
`, 1},
		// #919: rules that read keys a job inherits from a template in this file.
		{"GL008 never-runs rules from extends", "GL008", `
.off:
  rules:
    - when: never
semgrep-sast:
  extends: .off
`, 1},
		{"GL008 template in another file", "GL008", `
semgrep-sast:
  extends: .from-include
`, 0},
		{"GL014 dotenv artifact from extends", "GL014", `
.env:
  artifacts:
    reports:
      dotenv: build.env
build:
  extends: .env
  script: [env > build.env]
`, 1},
		{"GL014 template in another file", "GL014", `
build:
  extends: .from-include
  script: [env > build.env]
`, 0},
		{"GL044 MR rules from extends", "GL044", `
.mr:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
test:
  extends: .mr
  script: [git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA]
`, 1},
		{"GL044 template in another file", "GL044", `
test:
  extends: .from-include
  script: [git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA]
`, 0},
		{"GL046 unprotected cache from extends", "GL046", `
.cache:
  cache:
    key: deps
    unprotect: true
    paths: [vendor/]
test:
  extends: .cache
  script: [make test]
`, 1},
		{"GL046 template in another file", "GL046", `
test:
  extends: .from-include
  script: [make test]
`, 0},
		{"GL051 job inputs from extends", "GL051", `
.inputs:
  inputs:
    version:
      default: v1
deploy:
  extends: .inputs
  script:
    - ./deploy.sh ${{ job.inputs.version }}
`, 1},
		{"GL051 template in another file", "GL051", `
deploy:
  extends: .from-include
  script:
    - ./deploy.sh ${{ job.inputs.version }}
`, 0},
		{"GL071 manual from extends", "GL071", `
stages: [approve, deploy]
.manual:
  when: manual
approve_prod:
  extends: .manual
  stage: approve
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`, 1},
		{"GL071 template in another file", "GL071", `
stages: [approve, deploy]
approve_prod:
  extends: .from-include
  stage: approve
  script: [echo approved]
deploy_prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`, 0},
		{"GL080 no guard in the template either", "GL080", `
.deploy_base:
  image: alpine:3.20.3
deploy-prod:
  extends: .deploy_base
  stage: deploy
  script: [./deploy.sh]
`, 1},
		{"GL080 guard from extends", "GL080", `
.deploy_base:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
deploy-prod:
  extends: .deploy_base
  stage: deploy
  script: [./deploy.sh]
`, 0},
		{"GL081 id_tokens from extends, no guard", "GL081", `
.oidc:
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
oidc-job:
  extends: .oidc
  script: [./run.sh]
`, 1},
		{"GL081 guard from extends", "GL081", `
.oidc:
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
oidc-job:
  extends: .oidc
  script: [./run.sh]
`, 0},
		{"GL037 trigger from extends", "GL037", `
variables:
  DEPLOY_TOKEN: $DEPLOY_TOKEN
.trigger:
  trigger:
    project: group/other
child:
  extends: .trigger
`, 1},
		{"GL037 merged template reported once", "GL037", `
variables:
  DEPLOY_TOKEN: $DEPLOY_TOKEN
.trigger: &trigger
  trigger:
    project: group/other
child:
  <<: *trigger
`, 1},
		{"GL037 template in another file", "GL037", `
variables:
  DEPLOY_TOKEN: $DEPLOY_TOKEN
child:
  extends: .from-include
`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.yaml), "test.yml")
			if err != nil {
				t.Fatal(err)
			}
			rules := map[string]interface {
				Check(doc *yaml.Node, file string) []finding.Finding
			}{
				"GL005": GL005, "GL008": GL008, "GL014": GL014, "GL017": GL017, "GL019": GL019, "GL034": GL034,
				"GL037": GL037, "GL044": GL044, "GL046": GL046, "GL051": GL051, "GL071": GL071, "GL080": GL080,
				"GL081": GL081,
			}
			if got := rules[tc.rule].Check(doc.Root, "test.yml"); len(got) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(got), got)
			}
		})
	}
}

func TestInheritanceEffective(t *testing.T) {
	doc, err := parser.Parse([]byte(`
.a:
  image: a:1
  variables: {X: a, Y: a}
  tags: [a]
.b:
  extends: .a
  variables: {Y: b, Z: b}
.c:
  image: c:1
job:
  extends: [.b, .c]
  variables: {Z: job}
  tags: [job]
  script: [run]
loop:
  extends: .loop2
.loop2:
  extends: loop
  image: l:1
plain:
  script: [run]
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	in := NewInheritance(doc.Root)
	jobs := map[string]*yaml.Node{}
	parser.EachJob(doc.Root, func(name, job *yaml.Node) { jobs[name.Value] = job })

	job := in.Effective(jobs["job"])
	scalar := func(n *yaml.Node, path ...string) string {
		for _, k := range path {
			n = parser.FindKey(n, k)
		}
		if n == nil {
			return ""
		}
		return n.Value
	}
	for path, want := range map[string]string{
		"image":       "c:1", // the later extends: entry wins
		"variables X": "a",   // mappings merge through the chain
		"variables Y": "b",
		"variables Z": "job", // the job's own value wins
	} {
		if got := scalar(job, strings.Fields(path)...); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
	if tags := parser.FindKey(job, "tags"); len(tags.Content) != 1 || tags.Content[0].Value != "job" {
		t.Errorf("a list is replaced, not merged: got %v", tags.Content)
	}
	if parser.FindKey(jobs["job"], "image") != nil {
		t.Error("Effective must not change the job node")
	}
	if got := scalar(in.Effective(jobs["loop"]), "image"); got != "l:1" {
		t.Errorf("an extends: cycle still merges what it reaches once: image = %q", got)
	}
	if in.Effective(jobs["plain"]) != jobs["plain"] {
		t.Error("a job without extends: is returned as is")
	}
}
