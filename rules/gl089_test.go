// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings089(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL089.Check(doc.Root, "test.yml")
}

func TestGL089_Flagged(t *testing.T) {
	cases := map[string]string{
		"variable": `
renovate:
  image: renovate/renovate:39
  variables:
    RENOVATE_AUTODISCOVER: "true"
  script:
    - renovate --platform=gitlab
`,
		"yaml boolean": `
renovate:
  variables:
    RENOVATE_AUTODISCOVER: true
  script: [renovate]
`,
		"flag": `
renovate:
  script:
    - renovate --platform=gitlab --autodiscover
`,
		"flag with value": `
renovate:
  script:
    - npx --yes renovate --autodiscover=true
`,
		"global variable": `
variables:
  RENOVATE_AUTODISCOVER: "true"
renovate:
  script:
    - LOG_LEVEL=debug renovate
`,
		"workflow rules variable": `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
      variables:
        RENOVATE_AUTODISCOVER: "true"
renovate:
  script: [renovate]
`,
		"template via extends": `
.renovate:
  image: renovate/renovate:39
  variables:
    RENOVATE_AUTODISCOVER: "true"
  script: [renovate]
renovate:
  extends: .renovate
`,
		"filter for another flag's command": `
renovate:
  script:
    - renovate --autodiscover && echo "--autodiscover-filter group/*"
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings089(t, src)
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Severity != finding.Warn || f[0].Job != "renovate" {
				t.Errorf("unexpected finding: %+v", f[0])
			}
		})
	}
}

func TestGL089_NoFinding(t *testing.T) {
	cases := map[string]string{
		"filter variable": `
renovate:
  variables:
    RENOVATE_AUTODISCOVER: "true"
    RENOVATE_AUTODISCOVER_FILTER: "my-group/*"
  script: [renovate]
`,
		"namespaces variable": `
renovate:
  variables:
    RENOVATE_AUTODISCOVER: "true"
    RENOVATE_AUTODISCOVER_NAMESPACES: my-group
  script: [renovate]
`,
		"topics flag": `
renovate:
  script:
    - renovate --autodiscover --autodiscover-topics=renovate
`,
		"filter flag": `
renovate:
  variables:
    RENOVATE_AUTODISCOVER: "true"
  script:
    - renovate --autodiscover-filter "my-group/*"
`,
		"global filter": `
variables:
  RENOVATE_AUTODISCOVER_FILTER: "my-group/*"
renovate:
  variables:
    RENOVATE_AUTODISCOVER: "true"
  script: [renovate]
`,
		"filter in the extending job": `
.renovate:
  variables:
    RENOVATE_AUTODISCOVER: "true"
  script: [renovate]
renovate:
  extends: .renovate
  variables:
    RENOVATE_AUTODISCOVER_FILTER: "my-group/*"
`,
		"flag switches it off": `
renovate:
  variables:
    RENOVATE_AUTODISCOVER: "true"
  script:
    - renovate --autodiscover=false my-group/my-project
`,
		"no autodiscover": `
renovate:
  script:
    - renovate my-group/my-project
`,
		"autodiscover false": `
renovate:
  variables:
    RENOVATE_AUTODISCOVER: "false"
  script: [renovate]
`,
		"global variable not inherited": `
variables:
  RENOVATE_AUTODISCOVER: "true"
renovate:
  inherit:
    variables: false
  script: [renovate]
`,
		"hidden template alone": `
.renovate:
  variables:
    RENOVATE_AUTODISCOVER: "true"
  script: [renovate]
`,
		"not the renovate command": `
lint:
  variables:
    RENOVATE_AUTODISCOVER: "true"
  script:
    - npm install -g renovate
    - renovate-config-validator
    - echo renovate
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings089(t, src); len(f) != 0 {
				t.Fatalf("expected no finding, got %v", f)
			}
		})
	}
}
