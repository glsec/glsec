// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings027(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL027.Check(doc.Root, "test.yml")
}

func TestGL027_LongFormValue(t *testing.T) {
	f := findings027(t, `
variables:
  DEPLOY_PASSWORD:
    value: "staging-pw-2024"
    description: "Password for the staging deploy user"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
	if strings.Contains(f[0].Message, "masked: true") {
		t.Errorf("message must not recommend masked: true: %s", f[0].Message)
	}
}

// masked: is not a .gitlab-ci.yml keyword (#698), so it changes nothing.
func TestGL027_MaskedKeyDoesNotHelp(t *testing.T) {
	f := findings027(t, `
variables:
  DEPLOY_PASSWORD:
    value: "staging-pw-2024"
    masked: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding despite masked: true, got %d", len(f))
	}
}

func TestGL027_NoLiteralValue_NoFinding(t *testing.T) {
	for name, src := range map[string]string{ //nolint:gosec // G101: test inputs for the rule, not real secrets
		"description only": `
variables:
  DEPLOY_TOKEN:
    description: "Paste a deploy token when you run the pipeline"
`,
		"empty value": `
variables:
  DEPLOY_TOKEN:
    value: ""
    description: "Paste a deploy token"
`,
		"variable reference": `
variables:
  DEPLOY_TOKEN:
    value: $PROJECT_DEPLOY_TOKEN
`,
		"placeholder": `
variables:
  DEPLOY_TOKEN:
    value: "changeme"
`,
		"known token format, reported by GL006": `
variables:
  DEPLOY_TOKEN:
    value: "glpat-abcdefghijklmnopqrstuvwxyz"
`,
	} {
		if f := findings027(t, src); len(f) != 0 {
			t.Errorf("%s: expected no finding, got %d", name, len(f))
		}
	}
}

func TestGL027_ScalarForm_NoFinding(t *testing.T) {
	f := findings027(t, `
variables:
  POSTGRES_PASSWORD: postgres
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for scalar form, got %d", len(f))
	}
}

func TestGL027_NonSecretName_NoFinding(t *testing.T) {
	f := findings027(t, `
variables:
  DEPLOY_ENV:
    value: "staging"
    description: "Environment"
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for non-secret name, got %d", len(f))
	}
}

func TestGL027_SecretSuffixes(t *testing.T) {
	for _, name := range []string{
		"MY_TOKEN", "MY_SECRET", "MY_PASSWORD", "MY_PASSWD", "MY_PASS",
		"MY_PWD", "MY_KEY", "MY_CREDENTIAL", "MY_CERT", "MY_API_KEY",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			f := findings027(t, `
variables:
  `+name+`:
    value: "abc123"
`)
			if len(f) != 1 {
				t.Errorf("%s: expected 1 finding, got %d", name, len(f))
			}
		})
	}
}

func TestGL027_JobLevel(t *testing.T) {
	f := findings027(t, `
deploy:
  variables:
    DB_PASSWORD:
      value: "secret"
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for job-level variable, got %d", len(f))
	}
	if f[0].Job != "deploy" {
		t.Errorf("expected job name 'deploy', got %q", f[0].Job)
	}
}

func TestGL027_TopLevelMultiple(t *testing.T) {
	f := findings027(t, `
variables:
  PLAIN_VAR: "hello"
  API_TOKEN:
    value: "secret"
  DB_PASSWORD:
    value: $DB_PASSWORD_FROM_SETTINGS
  SSH_KEY:
    value: "key"
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (API_TOKEN and SSH_KEY), got %d", len(f))
	}
}

// Values written as a placeholder are not committed secrets (#991).
func TestGL027_PlaceholderShapes(t *testing.T) {
	for value, want := range map[string]int{
		"_api_token_":         0,
		"<your admin token>":  0,
		"{{ api_token }}":     0,
		"xxxxxxxx":            0,
		"TODO":                0,
		"replace-me":          0,
		"API_TOKEN":           0,
		"s3cr3t-Value-91x":    1,
		"prod_token_9f8e7d6c": 1,
	} {
		f := findings027(t, "variables:\n  API_TOKEN:\n    value: \""+value+"\"\n    description: the API token\nbuild:\n  script: [echo ok]\n")
		if len(f) != want {
			t.Errorf("%q: got %d findings, want %d", value, len(f), want)
		}
	}
}
