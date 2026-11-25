// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// A Pages job that publishes the whole working directory, or copies it into
// the publish directory with .git, serves .git on the site (#1499; verified on
// GitLab.com: .git/HEAD, .git/config and dotfiles return 200).
func TestGL005_PagesPublish(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"publish dot", `
create-pages:
  script: [echo]
  pages:
    publish: .
`, 1},
		{"publish CI_PROJECT_DIR", `
pages:
  script: [echo]
  pages:
    publish: $CI_PROJECT_DIR
`, 1},
		{"legacy publish dot", `
pages:
  script: [echo]
  publish: ./
`, 1},
		{"legacy publish dot with artifacts dot reported once", `
pages:
  script: [echo]
  publish: .
  artifacts:
    paths: [.]
    expire_in: 1 day
`, 1},
		{"publish public", `
pages:
  script: [echo]
  pages:
    publish: public
`, 0},
		{"publish dot on a non-Pages job is not a Pages publish", `
build:
  script: [echo]
  publish: .
`, 0},
		{"pages false", `
build:
  script: [echo]
  pages: false
  publish: .
`, 0},
		{"rsync into public", `
pages:
  script:
    - mkdir -p public
    - rsync -av --exclude=public ./ public/
  artifacts:
    paths: [public]
    expire_in: 1 day
`, 1},
		{"rsync into the publish directory", `
pages:
  script:
    - rsync -a --exclude dist . dist
  pages:
    publish: dist
`, 1},
		{"rsync excludes .git", `
pages:
  script:
    - rsync -av --exclude=.git --exclude=public . public/
`, 0},
		{"rsync includes only some files", `
pages:
  script:
    - rsync -a --include '*/' --include '*.json' --exclude '*' ./ ./public/
`, 0},
		{"rsync without recursion", `
pages:
  script:
    - rsync --exclude=public . public/
`, 0},
		{"cp that goes on after failing", `
pages:
  script:
    - mkdir public
    - cp -r . public/ || true
`, 1},
		{"cp into itself fails the job", `
pages:
  script:
    - mkdir public
    - cp -r . public
`, 0},
		{".git removed afterwards", `
pages:
  script:
    - cp -r . public/ 2>/dev/null || true
    - rm -rf public/.git public/public
`, 0},
		{"cp of the files", `
pages:
  script:
    - mkdir .public
    - cp -r * .public
    - mv .public public
`, 0},
		{"rsync in a non-Pages job", `
build:
  script:
    - rsync -a . public/
`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got int
			for _, f := range checkRule(t, GL005, tc.yaml) {
				if strings.Contains(f.Message, "Pages") || strings.Contains(f.Message, "whole working directory") {
					got++
				}
			}
			if got != tc.want {
				t.Fatalf("expected %d Pages findings, got %d: %v", tc.want, got, checkRule(t, GL005, tc.yaml))
			}
		})
	}
}
