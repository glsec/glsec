// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings043(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL043.Check(doc.Root, "test.yml")
}

func TestGL043_PrefixMatchBranch(t *testing.T) {
	f := findings043(t, `
deploy-prod:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^release/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for prefix match, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL043_NoAnchorsBranch(t *testing.T) {
	f := findings043(t, `
deploy-prod:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH =~ /release/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unanchored match, got %d", len(f))
	}
}

func TestGL043_FullyAnchoredNoFinding(t *testing.T) {
	f := findings043(t, `
deploy-prod:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^release$/
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for fully anchored pattern, got %d", len(f))
	}
}

func TestGL043_UserLoginPrefixMatch(t *testing.T) {
	f := findings043(t, `
privileged-job:
  script: [./admin.sh]
  rules:
    - if: $GITLAB_USER_LOGIN =~ /^admin/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for user login prefix match, got %d", len(f))
	}
}

func TestGL043_UserLoginFullyAnchoredNoFinding(t *testing.T) {
	f := findings043(t, `
privileged-job:
  script: [./admin.sh]
  rules:
    - if: $GITLAB_USER_LOGIN =~ /^admin$/
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for fully anchored user login, got %d", len(f))
	}
}

func TestGL043_NamespacePrefixMatch(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_PROJECT_NAMESPACE =~ /^myteam/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for namespace prefix match, got %d", len(f))
	}
}

func TestGL043_NamespaceSlashPrefix_NoFinding(t *testing.T) {
	f := findings043(t, `
build:
  script: [make]
  rules:
    - if: $CI_PROJECT_NAMESPACE =~ /^mygroup\//
    - if: $CI_PROJECT_NAMESPACE =~ /^mygroup\/sub\//
    - if: $CI_PROJECT_NAMESPACE =~ /^my\.group\//
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for a namespace prefix ending in /, got %d: %v", len(f), f)
	}
}

func TestGL043_NamespaceSlashPrefix_StillFlagged(t *testing.T) {
	f := findings043(t, `
build:
  script: [make]
  rules:
    - if: $CI_PROJECT_NAMESPACE =~ /^mygroup/
    - if: $CI_COMMIT_REF_NAME =~ /^release/
    - if: $CI_PROJECT_NAMESPACE =~ /^my.group\//
`)
	if len(f) != 3 {
		t.Fatalf("expected 3 findings (bare namespace prefix, ref-name prefix, non-literal namespace prefix), got %d: %v", len(f), f)
	}
}

func TestGL043_RefNamePrefixMatch(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_REF_NAME =~ /^v/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ref name prefix match, got %d", len(f))
	}
}

func TestGL043_WorkflowRules(t *testing.T) {
	f := findings043(t, `
workflow:
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^release/

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in workflow rules, got %d", len(f))
	}
}

func TestGL043_EqualityNoFinding(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for == operator, got %d", len(f))
	}
}

func TestGL043_UnrelatedVariableNoFinding(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_PIPELINE_SOURCE =~ /^push/
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for non-target variable, got %d", len(f))
	}
}

func TestGL043_MultipleConditionsOneUnanchored(t *testing.T) {
	f := findings043(t, `
deploy:
  script: [./deploy.sh]
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^main$/ && $GITLAB_USER_LOGIN =~ /^admin/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (only the unanchored pattern), got %d", len(f))
	}
}

func TestGL043_NoRulesNoFinding(t *testing.T) {
	f := findings043(t, `
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when no rules block, got %d", len(f))
	}
}

func TestGL043_EscapedSlash(t *testing.T) {
	doc := `
deploy:
  rules:
    - if: $CI_COMMIT_BRANCH =~ /^release\/\d+\.\d+$/
    - if: $CI_COMMIT_REF_NAME =~ /^feature\/x$/i
    - if: $CI_COMMIT_BRANCH =~ /^staging\//
  script:
    - ./deploy.sh
`
	f := findings043(t, doc)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (only the unanchored staging pattern), got %d: %v", len(f), f)
	}
	if !strings.Contains(f[0].Message, `/^staging\//`) || !strings.Contains(f[0].Message, `"staging/"`) {
		t.Errorf("message should quote the whole pattern and the plain prefix: %s", f[0].Message)
	}
}

// isLiteralNamespacePrefix accepts only a literal group path ending in \/;
// anything that could match another group is rejected (#820).
func TestIsLiteralNamespacePrefix(t *testing.T) {
	for pattern, want := range map[string]bool{
		`^mygroup\/`:        true,
		`\Amy-group\/sub\/`: true,
		`^my\.group\/`:      true,
		`^my_group\/`:       true,
		`^mygroup`:          false, // no trailing \/
		`^\/`:               false, // empty prefix
		`^my\\/`:            false, // a lone backslash is left before the final \/
		`^my\d\/`:           false, // escape other than . - _ /
		`^my.group\/`:       false, // unescaped dot matches any character
		`^my[a-z]\/`:        false, // character class
	} {
		if got := isLiteralNamespacePrefix(pattern); got != want {
			t.Errorf("isLiteralNamespacePrefix(%q) = %v, want %v", pattern, got, want)
		}
	}
}

// Patterns that can't be widened: a when: never rule, a trailing .+ or
// (.*), and an escaped slash read the way GitLab's lexer reads it (#987).
func TestGL043_NoBypassPossible(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want int
	}{
		{"- if: $CI_COMMIT_BRANCH =~ /wip/\n      when: never", 0},
		{`- if: $CI_COMMIT_BRANCH =~ /^prerelease\/.+/`, 0},
		{`- if: $CI_COMMIT_BRANCH =~ /^release\/(.*)/`, 0},
		{`- if: $CI_COMMIT_BRANCH =~ /^(fix|hotfix)((-|\\/)[a-z-]+)?$/`, 0},
		{`- if: $CI_COMMIT_BRANCH =~ /^release\.+/`, 1},
		{`- if: $CI_COMMIT_BRANCH =~ /^release/`, 1},
		{"- if: $CI_COMMIT_BRANCH =~ /wip/\n      when: always", 1},
	} {
		doc, err := parser.Parse([]byte("workflow:\n  rules:\n    "+tc.rule+"\njob:\n  script: [x]\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL043.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.rule, got, tc.want)
		}
	}
}
