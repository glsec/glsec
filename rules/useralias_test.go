// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/rule"
)

// A .gitlab-ci.yml variable whose value references a user-controlled
// predefined variable is user-controlled too: GitLab expands it recursively
// before the job runs (#1504).
func TestUserAliases(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    rule.Rule
		yaml string
		want int
	}{
		{"GL002 eval through a global alias", GL002, `
variables:
  BRANCH: $CI_COMMIT_REF_NAME
build:
  script:
    - eval "echo $BRANCH"
`, 1},
		{"GL002 through a job alias and a chain", GL002, `
variables:
  REF: ${CI_COMMIT_REF_NAME}
build:
  variables:
    NAME: release-$REF
  script:
    - sh -c "deploy $NAME"
`, 1},
		{"GL002 info not reported through an alias", GL002, `
variables:
  BRANCH: $CI_COMMIT_REF_NAME
build:
  script:
    - echo $BRANCH
`, 0},
		{"GL002 expand false is literal", GL002, `
variables:
  BRANCH:
    value: $CI_COMMIT_REF_NAME
    expand: false
build:
  script:
    - eval "echo $BRANCH"
`, 0},
		{"GL002 escaped dollar", GL002, `
variables:
  BRANCH: $CI_COMMIT_REF_NAME
build:
  script:
    - eval "echo $$BRANCH"
`, 0},
		{"GL002 job variable overrides the global alias", GL002, `
variables:
  BRANCH: $CI_COMMIT_REF_NAME
build:
  variables:
    BRANCH: main
  script:
    - eval "echo $BRANCH"
`, 0},
		{"GL015 image tag through an alias", GL015, `
variables:
  IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
build:
  script:
    - docker build -t "$IMAGE_TAG" .
    - docker push "$IMAGE_TAG"
`, 2},
		{"GL015 per-commit alias", GL015, `
variables:
  IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
build:
  script:
    - docker push "$IMAGE_TAG"
`, 0},
		{"GL025 curl through an alias", GL025, `
variables:
  BRANCH: $CI_COMMIT_REF_NAME
upload:
  script:
    - curl -X PUT "https://example.com/upload/$BRANCH/app.tar.gz"
`, 1},
		{"GL052 environment name through a job alias", GL052, `
deploy:
  variables:
    TARGET: $CI_COMMIT_REF_NAME
  environment:
    name: $TARGET
  script:
    - ./deploy.sh
`, 1},
		{"GL046 cache key through an alias", GL046, `
variables:
  KEY: $CI_COMMIT_REF_NAME
build:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  cache:
    key: $KEY
    unprotect: true
    paths: [vendor/]
  script:
    - make
`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkRule(t, tc.r, tc.yaml)
			if len(got) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(got), got)
			}
			for _, f := range got {
				if !strings.Contains(f.Message, "through variables: $") {
					t.Errorf("message should name the alias: %s", f.Message)
				}
			}
		})
	}
}
