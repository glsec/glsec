// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.yaml), "test.yml")
			if err != nil {
				t.Fatal(err)
			}
			rules := map[string]interface {
				Check(doc *yaml.Node, file string) []finding.Finding
			}{"GL005": GL005, "GL017": GL017, "GL019": GL019, "GL034": GL034}
			if got := rules[tc.rule].Check(doc.Root, "test.yml"); len(got) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(got), got)
			}
		})
	}
}
