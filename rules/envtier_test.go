// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// The tier GitLab guesses from an environment's name when deployment_tier
// isn't set (#989), and an explicit tier winning over the name.
func TestEnvTier(t *testing.T) {
	for _, tc := range []struct {
		env, tier string
		explicit  bool
	}{
		{"review/$CI_COMMIT_REF_SLUG", "development", false},
		{"dev", "development", false},
		{"integration", "testing", false},
		{"qa", "testing", false},
		{"staging", "staging", false},
		{"preview", "development", false}, // "review" comes first, as in GitLab
		{"pre-production", "staging", false},
		{"production", "production", false},
		{"live", "production", false},
		{"e2e", "other", false},
		{"{name: production, deployment_tier: development}", "development", true},
		{"{name: review/x, deployment_tier: production}", "production", true},
		{"{name: integration}", "testing", false},
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(tc.env), &n); err != nil {
			t.Fatal(err)
		}
		if tier, explicit := envTier(n.Content[0]); tier != tc.tier || explicit != tc.explicit {
			t.Errorf("%s: got %s (explicit %v), want %s (explicit %v)", tc.env, tier, explicit, tc.tier, tc.explicit)
		}
	}
}

func TestGL049_PagesAndTestJobs(t *testing.T) {
	src := `default:
  interruptible: true
pages:
  stage: deploy
  script: [mkdir -p public]
  artifacts:
    paths: [public]
docs:
  stage: deploy
  pages: true
  script: [mkdir -p public]
test:e2e:
  stage: test
  environment:
    name: e2e
    url: http://nginx:8080/
  script: [./e2e.sh]
deploy-prod:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := GL049.Check(doc.Root, "test.yml")
	if len(f) != 1 || f[0].Job != "deploy-prod" {
		t.Errorf("got %v, want one finding for deploy-prod", f)
	}
}

func TestGL019_TierFromEnvironmentName(t *testing.T) {
	src := `review:
  stage: review
  environment:
    name: review/$CI_COMMIT_REF_SLUG
  script: [./deploy-review.sh]
integration:
  stage: verify
  environment: integration
  script: [./deploy-int.sh]
production:
  stage: deploy
  environment: production
  script: [./deploy.sh]
`
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := GL019.Check(doc.Root, "test.yml")
	if len(f) != 1 || f[0].Job != "production" {
		t.Errorf("got %v, want one finding for production", f)
	}
}
