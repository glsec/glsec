// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	gitlabver "github.com/glsec/glsec/internal/version"
)

func findingsFor(t *testing.T, src string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	found, _, _, _ := collectFindings(doc, "test.yml", config.Default(), gitlabver.Version{}, true, true)
	return found
}

// Configuration pulled in through a YAML anchor must be checked like the same
// configuration written inline.
func TestCollectFindings_AnchoredConfig(t *testing.T) {
	const workflow = "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == \"main\"\n"
	cases := []struct {
		name, rule, src string
	}{
		{"script alias", "GL011", `.steps: &steps
  - curl -s https://x.example/i.sh | bash
build:
  image: node:22.1.0
  tags: [x]
  script: *steps
`},
		{"script list-item alias", "GL011", `.steps: &steps
  - curl -s https://x.example/i.sh | bash
build:
  image: node:22.1.0
  tags: [x]
  script:
    - *steps
    - make
`},
		{"image alias", "GL001", `.img: &img node:latest
build:
  image: *img
  tags: [x]
  script: [make]
`},
		{"cache alias", "GL046", `.c: &c
  key: $CI_COMMIT_REF_NAME
  paths: [x/]
build:
  image: node:22.1.0
  tags: [x]
  cache: *c
  script: [make]
`},
		{"variables merge key", "GL066", `.v: &v
  DOCKER_AUTH_CONFIG: '{"auths":{"r":{"auth":"dXNlcjpwYXNz"}}}'
build:
  image: node:22.1.0
  tags: [x]
  variables:
    <<: *v
  script: [make]
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range findingsFor(t, workflow+tc.src) {
				if f.RuleID == tc.rule {
					return
				}
			}
			t.Errorf("expected %s on anchored configuration", tc.rule)
		})
	}
}

func TestCollectFindings_AnchorUsedByManyJobsReportedOnce(t *testing.T) {
	found := findingsFor(t, `workflow:
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
.img: &img node:latest
a:
  image: *img
  tags: [x]
  script: [make]
b:
  image: *img
  tags: [x]
  script: [make]
c:
  image: *img
  tags: [x]
  script: [make]
`)
	n := 0
	for _, f := range found {
		if f.RuleID == "GL001" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected one GL001 finding at the anchor, got %d", n)
	}
}
