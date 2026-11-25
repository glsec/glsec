// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// A rules: entry that matches on any branch lets that branch mint the token,
// whatever the other entries restrict: GitLab runs the job by the first entry
// that matches (#1491).
func TestGL081_OpenRulesEntry(t *testing.T) {
	for _, tc := range []struct {
		name, rules string
		want        int
		why         string
	}{
		{"manual fallback after main", "- if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: manual", 1, "when: manual has no if:"},
		{"changes only", "- changes: [infra/**]", 1, "with changes: and no if:"},
		{"exists only", "- exists: [main.tf]", 1, "with exists: and no if:"},
		{"branch presence", "- if: $CI_COMMIT_BRANCH", 1, "only checks that a branch is set"},
		{"branch presence with changes", "- if: $CI_COMMIT_BRANCH\n      changes: [infra/**]", 1, "only checks that a branch is set"},
		{"unrelated exclusion first", "- if: $CI_COMMIT_MESSAGE =~ /skip/\n      when: never\n    - when: on_success", 1, "when: on_success"},
		// Still silent.
		{"default branch", "- if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH", 0, ""},
		{"default branch and tags", "- if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - if: $CI_COMMIT_TAG", 0, ""},
		{"restricting if with changes", "- if: $CI_COMMIT_BRANCH == \"main\"\n      changes: [infra/**]", 0, ""},
		{"protected excluded first", "- if: $CI_COMMIT_REF_PROTECTED != \"true\"\n      when: never\n    - when: manual", 0, ""},
		{"non-default excluded first", "- if: $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH\n      when: never\n    - changes: [infra/**]", 0, ""},
		{"no tag excluded first", "- if: $CI_COMMIT_TAG == null\n      when: never\n    - when: on_success", 0, ""},
		{"never fallback", "- if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: never", 0, ""},
		{"schedule", "- if: $CI_PIPELINE_SOURCE == \"schedule\"", 0, ""},
		{"web", "- if: $CI_PIPELINE_SOURCE == \"web\"\n      when: manual", 0, ""},
		{"own variable", "- if: $DEPLOY == \"true\"", 0, ""},
		{"unresolved reference first", "- !reference [.elsewhere, rules]\n    - when: manual", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y := "oidc:\n  rules:\n    " + tc.rules + "\n  id_tokens:\n    AWS_TOKEN: {aud: https://sts.amazonaws.com}\n  script: [aws sts get-caller-identity]\n"
			f := findings081(t, y)
			if len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v\n%s", len(f), tc.want, f, y)
			}
			if tc.want == 1 {
				m := f[0].Message
				if f[0].Severity != finding.Warn || f[0].Line != 1 || !strings.Contains(m, tc.why) || !strings.Contains(m, "OIDC token AWS_TOKEN (id_tokens:)") || !strings.Contains(m, "any branch can mint") {
					t.Errorf("got %s line %d %q, want warn at the job naming %q", f[0].Severity, f[0].Line, m, tc.why)
				}
			}
		})
	}
}

// A workflow that keeps unprotected refs out still silences the file; a
// workflow that admits branches doesn't.
func TestGL081_OpenRulesEntryWorkflow(t *testing.T) {
	job := "oidc:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - when: manual\n  id_tokens:\n    T: {aud: https://sts.amazonaws.com}\n  script: [./x]\n"
	if f := findings081(t, "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n    - if: $CI_COMMIT_TAG\n"+job); len(f) != 0 {
		t.Errorf("protected workflow: got %v, want none", f)
	}
	if f := findings081(t, "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n"+job); len(f) != 1 {
		t.Errorf("branch workflow: got %v, want one finding", f)
	}
}

// identity: credentials and declared read-only audiences get the open-entry
// wording too; the audience downgrade to info still applies.
func TestGL081_OpenRulesEntryIdentityAndRestricted(t *testing.T) {
	f := findings081(t, "gcp:\n  identity: google_cloud\n  rules:\n    - changes: [infra/**]\n  script: [./x]\n")
	if len(f) != 1 || !strings.Contains(f[0].Message, "identity:, but its rules: entry with changes:") {
		t.Errorf("identity: got %v", f)
	}
	GL081.SetRestrictedAudiences([]string{"ro"})
	t.Cleanup(func() { GL081.SetRestrictedAudiences(nil) })
	f = findings081(t, "plan:\n  rules:\n    - if: $CI_COMMIT_TAG\n    - when: manual\n  id_tokens:\n    T: {aud: ro}\n  script: [./x]\n")
	if len(f) != 1 || f[0].Severity != finding.Info || !strings.Contains(f[0].Message, "and its rules: entry when: manual") {
		t.Errorf("restricted audience: got %v", f)
	}
}

// A rules: block whose entries carry no condition at all was already
// reported as unguarded, with that wording.
func TestGL081_ConditionlessRulesKeepUnguardedWording(t *testing.T) {
	f := findings081(t, "oidc:\n  rules:\n    - when: manual\n  id_tokens:\n    T: {aud: https://sts.amazonaws.com}\n  script: [./x]\n")
	if len(f) != 1 || !strings.Contains(f[0].Message, "with no guard restricting") {
		t.Errorf("got %v, want the unguarded finding", f)
	}
}

// Inherited rules count where GitLab merges them.
func TestGL081_OpenRulesEntryInherited(t *testing.T) {
	f := findings081(t, `.deploy:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - when: manual
deploy:
  extends: .deploy
  id_tokens:
    T: {aud: https://sts.amazonaws.com}
  script: [./x]
`)
	if len(f) != 1 || f[0].Job != "deploy" {
		t.Errorf("got %v, want one finding in job deploy", f)
	}
}
