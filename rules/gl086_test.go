// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings086(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL086.Check(doc.Root, "test.yml")
}

func TestGL086_UnquotedColonInCurlHeader(t *testing.T) {
	f := findings086(t, `
deploy:
  script:
    - echo start
    - curl -H "Authorization: Bearer $DEPLOY_TOKEN" "https://hooks.example.com/deploy?branch=$CI_COMMIT_REF_NAME"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(f), f)
	}
	if f[0].Severity != finding.Error || f[0].Job != "deploy" || f[0].Line != 5 || f[0].Col != 7 {
		t.Errorf("unexpected finding: %+v", f[0])
	}
	if !strings.Contains(f[0].Message, `"curl -H \"Authorization"`) {
		t.Errorf("message should quote the key: %s", f[0].Message)
	}
}

func TestGL086_AllScriptSections(t *testing.T) {
	f := findings086(t, `
before_script:
  - echo a: b
default:
  after_script:
    - echo c: d
  hooks:
    pre_get_sources_script:
      - echo e: f
build:
  before_script:
    - echo g: h
  script:
    - - echo i: j
  after_script:
    - echo k: l
  hooks:
    pre_get_sources_script:
      - echo m: n
`)
	if len(f) != 7 {
		t.Fatalf("expected 7 findings, got %d: %v", len(f), f)
	}
}

// Quoting an argument does not help: the line starts as a plain scalar, so the
// colon inside the quotes still splits it.
func TestGL086_ColonInsideQuotedArgument(t *testing.T) {
	f := findings086(t, `
build:
  script:
    - echo "time: $(date)"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL086_LongKeyIsTruncated(t *testing.T) {
	f := findings086(t, `
build:
  script:
    - curl --silent --show-error --fail --location --header "X-Token: $T" https://example.com
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, `--fail --loca…"`) {
		t.Errorf("expected a truncated key in the message: %s", f[0].Message)
	}
}

func TestGL086_QuotedAndBlockScalarNoFinding(t *testing.T) {
	f := findings086(t, `
deploy:
  script:
    - 'curl -H "Authorization: Bearer $DEPLOY_TOKEN" https://hooks.example.com/deploy'
    - |
      curl -H "Authorization: Bearer $DEPLOY_TOKEN" https://hooks.example.com/deploy
    - echo key:value
    - curl https://example.com:8443/health
  variables:
    A: b
  rules:
    - if: $CI_COMMIT_BRANCH
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %v", f)
	}
}

func TestGL086_RunStepsNoFinding(t *testing.T) {
	f := findings086(t, `
build:
  run:
    - name: compile
      script: make all
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for run: steps, got %v", f)
	}
}
