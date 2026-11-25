// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// A job whose tokens only use audiences declared in restricted_oidc_audiences
// is reported as info; any undeclared or unmatchable audience keeps it a
// warning (#1484).
func TestGL081_RestrictedAudiences(t *testing.T) {
	GL081.SetRestrictedAudiences([]string{"https://idp.example.org/read-pool", "sts.example.org/ro"})
	t.Cleanup(func() { GL081.SetRestrictedAudiences(nil) })

	job := func(tokens string) string {
		return "plan:\n  id_tokens:\n" + tokens + "  script: [./plan.sh]\n"
	}
	for name, tc := range map[string]struct {
		tokens string
		want   finding.Severity
		names  string
	}{
		"declared":              {"    RO_TOKEN:\n      aud: https://idp.example.org/read-pool\n", finding.Info, "token RO_TOKEN"},
		"declared list":         {"    RO_TOKEN:\n      aud: [https://idp.example.org/read-pool, sts.example.org/ro]\n", finding.Info, "token RO_TOKEN"},
		"two declared tokens":   {"    A:\n      aud: sts.example.org/ro\n    B:\n      aud: https://idp.example.org/read-pool\n", finding.Info, "tokens A, B"},
		"undeclared":            {"    RW_TOKEN:\n      aud: https://idp.example.org/write-pool\n", finding.Warn, "token RW_TOKEN"},
		"list with undeclared":  {"    T:\n      aud: [https://idp.example.org/read-pool, https://sts.amazonaws.com]\n", finding.Warn, "token T"},
		"one undeclared token":  {"    RO:\n      aud: sts.example.org/ro\n    RW:\n      aud: https://sts.amazonaws.com\n", finding.Warn, "token RW"},
		"variable audience":     {"    T:\n      aud: $READ_POOL_AUD\n", finding.Warn, "token T"},
		"prefix is not a match": {"    T:\n      aud: https://idp.example.org/read-pool/extra\n", finding.Warn, "token T"},
		"trailing slash":        {"    T:\n      aud: https://idp.example.org/read-pool/\n", finding.Warn, "token T"},
		"no aud":                {"    T:\n      foo: bar\n", finding.Warn, "token T"},
	} {
		t.Run(name, func(t *testing.T) {
			f := findings081(t, job(tc.tokens))
			if len(f) != 1 {
				t.Fatalf("got %d findings, want 1: %v", len(f), f)
			}
			if f[0].Severity != tc.want || !strings.Contains(f[0].Message, "OIDC "+tc.names+" (id_tokens:)") {
				t.Errorf("got %s %q, want %s naming %q", f[0].Severity, f[0].Message, tc.want, tc.names)
			}
		})
	}
}

// The guard still decides whether there is a finding at all; a declared
// audience only lowers its severity, and the MR-admitting reason is kept.
func TestGL081_RestrictedAudienceKeepsGuardLogic(t *testing.T) {
	GL081.SetRestrictedAudiences([]string{"ro"})
	t.Cleanup(func() { GL081.SetRestrictedAudiences(nil) })

	if f := findings081(t, `plan:
  id_tokens:
    T: {aud: ro}
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  script: [./plan.sh]
`); len(f) != 0 {
		t.Errorf("guarded job: got %v, want none", f)
	}
	f := findings081(t, `plan:
  id_tokens:
    T: {aud: ro}
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script: [./plan.sh]
`)
	if len(f) != 1 || f[0].Severity != finding.Info || !strings.Contains(f[0].Message, "admits merge_request_event") {
		t.Errorf("MR job: got %v, want one info finding naming the MR guard", f)
	}
}

// The audience may come from a template through extends:.
func TestGL081_RestrictedAudienceInherited(t *testing.T) {
	GL081.SetRestrictedAudiences([]string{"ro"})
	t.Cleanup(func() { GL081.SetRestrictedAudiences(nil) })

	f := findings081(t, `.oidc:
  id_tokens:
    T: {aud: ro}
plan:
  extends: .oidc
  script: [./plan.sh]
`)
	if len(f) != 1 || f[0].Severity != finding.Info || f[0].Job != "plan" {
		t.Errorf("got %v, want one info finding in job plan", f)
	}
}

// Without the config key nothing changes, apart from the token name in the
// message; identity: credentials have no token to name.
func TestGL081_TokenNamedWithoutConfig(t *testing.T) {
	f := findings081(t, `plan:
  id_tokens:
    CLOUD_RO_TOKEN:
      aud: https://idp.example.org/read-pool
  script: [./plan.sh]
gcp:
  identity: google_cloud
  script: [./deploy.sh]
`)
	if len(f) != 2 {
		t.Fatalf("got %v, want two findings", f)
	}
	for _, x := range f {
		if x.Severity != finding.Warn {
			t.Errorf("%s: got %s, want warn", x.Job, x.Severity)
		}
	}
	if !strings.Contains(f[0].Message, "OIDC token CLOUD_RO_TOKEN (id_tokens:)") {
		t.Errorf("message does not name the token: %q", f[0].Message)
	}
	if !strings.Contains(f[1].Message, "identity:") {
		t.Errorf("identity message changed: %q", f[1].Message)
	}
}
