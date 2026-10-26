// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestSecretNameHeuristics(t *testing.T) {
	for _, tc := range []struct {
		name, rule, yaml string
		want             int
	}{
		{"GL059 _VERSION", "GL059", "b:\n  script:\n    - docker build --build-arg AUTH_VERSION=1 .\n", 0},
		{"GL059 _PACKAGE", "GL059", "b:\n  script:\n    - docker build --build-arg AUTH_PACKAGE=x .\n", 0},
		{"GL059 _ENDPOINT", "GL059", "b:\n  script:\n    - docker build --build-arg REACT_APP_AUTH0_TOKEN_ENDPOINT .\n", 0},
		{"GL059 secret", "GL059", "b:\n  script:\n    - docker build --build-arg NPM_TOKEN .\n", 1},
		{"GL018 composite value", "GL018", "variables:\n  SONAR_PROJECT_KEY: \"${CI_PROJECT_NAMESPACE}:${CI_PROJECT_NAME}\"\n", 0},
		{"GL018 predefined non-secret", "GL018", "variables:\n  NODE_MODULES_CACHE_KEY: ${CI_COMMIT_REF_SLUG}\n", 0},
		{"GL018 job token", "GL018", "variables:\n  TF_HTTP_PASSWORD: ${CI_JOB_TOKEN}\n", 0},
		{"GL018 registry password", "GL018", "variables:\n  DOCKER_PASSWORD: $CI_REGISTRY_PASSWORD\n", 0},
		{"GL018 project setting", "GL018", "variables:\n  DEPLOY_TOKEN: $PROD_DEPLOY_TOKEN\n", 1},
		{"GL018 CI_-named project setting", "GL018", "variables:\n  API_TOKEN: ${CI_API_TOKEN}\n", 1},
		{"GL037 literal values", "GL037", "variables:\n  MYSQL_PASSWORD: drupaltestbotpw\n  REPEAT_UNTIL_PASS: 5\n  TLS_SECRET: gitlab-ci-tls\nt:\n  trigger:\n    project: g/p\n", 0},
		{"GL037 forwarded setting", "GL037", "variables:\n  DEPLOY_TOKEN: $PROD_DEPLOY_TOKEN\nt:\n  trigger:\n    project: g/p\n", 1},
		{"GL037 inherit list without the secret", "GL037", "variables:\n  DEPLOY_TOKEN: $PROD_DEPLOY_TOKEN\n  ENV: prod\nt:\n  inherit:\n    variables: [ENV]\n  trigger:\n    project: g/p\n", 0},
		{"GL037 inherit list with the secret", "GL037", "variables:\n  DEPLOY_TOKEN: $PROD_DEPLOY_TOKEN\nt:\n  inherit:\n    variables: [DEPLOY_TOKEN]\n  trigger:\n    project: g/p\n", 1},
		{"GL021 runner short token", "GL021", "j:\n  script:\n    - echo $CI_RUNNER_SHORT_TOKEN\n", 0},
		{"GL021 TOKEN_ENDPOINT", "GL021", "j:\n  script:\n    - echo $OAUTH_TOKEN_ENDPOINT\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.yaml), "t.yml")
			if err != nil {
				t.Fatal(err)
			}
			var n int
			switch tc.rule {
			case "GL059":
				n = len(GL059.Check(doc.Root, "t.yml"))
			case "GL018":
				n = len(GL018.Check(doc.Root, "t.yml"))
			case "GL037":
				n = len(GL037.Check(doc.Root, "t.yml"))
			case "GL021":
				n = len(GL021.Check(doc.Root, "t.yml"))
			}
			if n != tc.want {
				t.Fatalf("expected %d findings, got %d", tc.want, n)
			}
		})
	}
}
