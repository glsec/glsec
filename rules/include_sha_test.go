// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

const testFullSHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func TestGL003_RequireIncludeSHA(t *testing.T) {
	for _, tc := range []struct {
		name, ref string
		enabled   bool
		severity  finding.Severity
	}{
		{"default version tag", "v1.2.3", false, ""},
		{"default short SHA", "deadbeef", false, ""},
		{"default other branch", "release", false, ""},
		{"default known branch", "main", false, finding.Error},
		{"version tag", "v1.2.3", true, finding.Warn},
		{"short SHA", "deadbeef", true, finding.Warn},
		{"other branch", "unstable/2024q4", true, finding.Warn},
		{"known branch stays error", "main", true, finding.Error},
		{"full SHA", testFullSHA, true, ""},
		{"own commit", "$CI_COMMIT_SHA", true, ""},
		{"unknown variable", "$TEMPLATE_REF", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &gl003{requireIncludeSHA: tc.enabled}
			doc, err := parser.Parse([]byte(fmt.Sprintf("include:\n  - project: acme/e\n    ref: %q\n    file: /e.yml\n", tc.ref)), "ci.yml")
			if err != nil {
				t.Fatal(err)
			}
			assertIncludeSeverity(t, r.Check(doc.Root, "ci.yml"), tc.severity)
		})
	}
}

func TestGL041_RequireIncludeSHA(t *testing.T) {
	for _, tc := range []struct {
		name, ref string
		enabled   bool
		severity  finding.Severity
	}{
		{"default version tag", "1.2.3", false, ""},
		{"default short SHA", "deadbeef", false, finding.Warn},
		{"version tag", "1.2.3", true, finding.Warn},
		{"v prefix", "v1.2.3", true, finding.Warn},
		{"prerelease", "1.2.3-rc.1", true, finding.Warn},
		{"short SHA", "deadbeef", true, finding.Warn},
		{"full SHA", testFullSHA, true, ""},
		{"own commit", "$CI_COMMIT_SHA", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &gl041{requireIncludeSHA: tc.enabled}
			doc, err := parser.Parse([]byte(fmt.Sprintf("include:\n  - component: gitlab.example.invalid/acme/g@%s\n", tc.ref)), "ci.yml")
			if err != nil {
				t.Fatal(err)
			}
			assertIncludeSeverity(t, r.Check(doc.Root, "ci.yml"), tc.severity)
		})
	}
}

// GL041 owns a component on a tag, so GL003 doesn't report it a second time.
func TestGL003_RequireIncludeSHALeavesComponentsToGL041(t *testing.T) {
	r := &gl003{requireIncludeSHA: true}
	doc, err := parser.Parse([]byte("include:\n  - component: gitlab.example.invalid/acme/g@1.2.3\n"), "ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if f := r.Check(doc.Root, "ci.yml"); len(f) != 0 {
		t.Errorf("expected no GL003 finding, got %v", f)
	}
}

// Under the policy no finding may suggest pinning to a tag.
func TestRequireIncludeSHA_AdviceNamesOnlyASHA(t *testing.T) {
	const pipeline = `include:
  - project: acme/e
    ref: main
    file: /e.yml
  - component: gitlab.example.invalid/acme/a
  - component: gitlab.example.invalid/acme/b@~latest
  - component: gitlab.example.invalid/acme/c@1.2
  - component: gitlab.example.invalid/acme/d@main
`
	doc, err := parser.Parse([]byte(pipeline), "ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	findings := (&gl003{requireIncludeSHA: true}).Check(doc.Root, "ci.yml")
	findings = append(findings, (&gl041{requireIncludeSHA: true}).Check(doc.Root, "ci.yml")...)
	if len(findings) != 8 {
		t.Fatalf("expected 8 findings, got %d: %v", len(findings), findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Message, "pin to a full commit SHA") || strings.Contains(strings.ToLower(f.Message), "pin to a tag") || strings.Contains(f.Message, "semver") {
			t.Errorf("%s advice: %s", f.RuleID, f.Message)
		}
	}
}

func assertIncludeSeverity(t *testing.T, f []finding.Finding, want finding.Severity) {
	t.Helper()
	if want == "" {
		if len(f) != 0 {
			t.Errorf("expected no finding, got %v", f)
		}
		return
	}
	if len(f) != 1 || f[0].Severity != want {
		t.Errorf("expected one %s finding, got %v", want, f)
	}
}
