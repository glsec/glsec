package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings084(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL084.Check(doc.Root, "test.yml")
}

func TestGL084_RefNameIsError(t *testing.T) {
	cases := map[string]string{
		"project ref": `
include:
  - project: my-group/ci-templates
    ref: $CI_COMMIT_REF_NAME
    file: /jobs/deploy.yml
`,
		"local path": `
include:
  - local: "/ci/${CI_COMMIT_REF_NAME}.yml"
`,
		"component path": `
include:
  - component: $CI_SERVER_FQDN/$CI_COMMIT_REF_NAME/scan@1.2.3
`,
	}

	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings084(t, yaml)
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Severity != finding.Error {
				t.Errorf("expected Error severity for CI_COMMIT_REF_NAME, got %s", f[0].Severity)
			}
			if !strings.Contains(f[0].Message, "CI_COMMIT_REF_NAME") {
				t.Errorf("message does not name the variable: %s", f[0].Message)
			}
		})
	}
}

func TestGL084_CustomVariableIsWarn(t *testing.T) {
	cases := map[string]string{
		"local":            "include:\n  - local: $TEMPLATE_PATH\n",
		"scalar shorthand": "include: $TEMPLATE_PATH\n",
		"sequence of scalars": `
include:
  - $TEMPLATE_PATH
`,
		"single mapping": `
include:
  local: $TEMPLATE_PATH
`,
		"project":        "include:\n  - project: $TEMPLATE_PROJECT\n    ref: 3a1f9c2b7e5d4a6f8c0b1d2e3f4a5b6c7d8e9f01\n    file: /a.yml\n",
		"braced":         "include:\n  - local: /ci/${TEMPLATE_NAME}.yml\n",
		"component path": "include:\n  - component: $CI_SERVER_FQDN/$COMPONENT_PROJECT/scan@1.2.3\n",
	}

	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings084(t, yaml)
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Severity != finding.Warn {
				t.Errorf("expected Warn severity, got %s", f[0].Severity)
			}
		})
	}
}

func TestGL084_FileSequence(t *testing.T) {
	f := findings084(t, `
include:
  - project: my-group/ci-templates
    ref: 3a1f9c2b7e5d4a6f8c0b1d2e3f4a5b6c7d8e9f01
    file:
      - /jobs/build.yml
      - $TEMPLATE_FILE
      - /ci/${CI_COMMIT_REF_NAME}.yml
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings across the file: list, got %d", len(f))
	}
}

func TestGL084_ServerControlledVariables(t *testing.T) {
	cases := map[string]string{
		"documented component idiom": "include:\n  - component: $CI_SERVER_FQDN/$CI_PROJECT_PATH/scan@1.2.3\n",
		"project path":               "include:\n  - project: $CI_PROJECT_PATH\n    ref: 3a1f9c2b7e5d4a6f8c0b1d2e3f4a5b6c7d8e9f01\n    file: /a.yml\n",
		"project namespace":          "include:\n  - project: $CI_PROJECT_NAMESPACE/ci\n    ref: 3a1f9c2b7e5d4a6f8c0b1d2e3f4a5b6c7d8e9f01\n    file: /a.yml\n",
		"server host":                "include:\n  - component: $CI_SERVER_HOST/my-group/scan@1.2.3\n",
		"api url":                    "include:\n  - local: $CI_API_V4_URL\n",
		"pipeline source":            "include:\n  - local: /ci/$CI_PIPELINE_SOURCE.yml\n",
		"default branch":             "include:\n  - project: my-group/ci\n    ref: $CI_DEFAULT_BRANCH\n    file: /a.yml\n",
		"no variables":               "include:\n  - local: /ci/build.yml\n  - template: Jobs/SAST.gitlab-ci.yml\n",
	}

	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings084(t, yaml); len(f) != 0 {
				t.Fatalf("expected no finding, got %d: %s", len(f), f[0].Message)
			}
		})
	}
}

func TestGL084_RemoteAndTemplateLeftAlone(t *testing.T) {
	f := findings084(t, `
include:
  - remote: https://example.com/${CI_COMMIT_REF_NAME}/pipeline.yml
  - template: $TEMPLATE_NAME
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for remote:/template:, got %d: %s", len(f), f[0].Message)
	}
}

func TestGL084_ComponentVersionLeftToGL041(t *testing.T) {
	f := findings084(t, `
include:
  - component: $CI_SERVER_FQDN/my-group/scan@$COMPONENT_VERSION
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for a variable version, got %d: %s", len(f), f[0].Message)
	}
}

func TestGL084_RefNameWinsOverCustomVariable(t *testing.T) {
	f := findings084(t, `
include:
  - local: /ci/$TEMPLATE_DIR/${CI_COMMIT_REF_NAME}.yml
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected the higher CI_COMMIT_REF_NAME severity, got %s", f[0].Severity)
	}
}

func TestGL084_ReportsPositionOfTheValue(t *testing.T) {
	f := findings084(t, `
include:
  - local: $TEMPLATE_PATH
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Line != 3 {
		t.Errorf("expected line 3, got %d", f[0].Line)
	}
}
