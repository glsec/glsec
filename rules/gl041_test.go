// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL041(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "component without version",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast`,
			wantHits: 1,
		},
		{
			name: "component with @latest",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@latest`,
			wantHits: 1,
		},
		{
			name: "component with @~latest",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@~latest`,
			wantHits: 1,
		},
		{
			name: "component with @main (branch name)",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@main`,
			wantHits: 1,
		},
		{
			name: "component with @feature-branch (branch slug, no dots)",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@feature-branch`,
			wantHits: 1,
		},
		{
			name: "component with semver tag — safe",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@1.0.0`,
			wantHits: 0,
		},
		{
			name: "component with v-prefixed semver tag — safe",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@v1.2.3`,
			wantHits: 0,
		},
		{
			name: "component with a two-segment version — the latest 2.1.x, not pinned (#986)",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@2.1`,
			wantHits: 1,
		},
		{
			name: "component with full SHA — safe",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@a3f1e9b2c4d5678901234567890abcdef1234567`,
			wantHits: 0,
		},
		{
			name: "multiple components mixed",
			yaml: `include:
  - component: gitlab.com/org/sast@1.0.0
  - component: gitlab.com/org/dast@latest
  - component: gitlab.com/org/fuzz`,
			wantHits: 2,
		},
		{
			name: "project include — not flagged by GL041",
			yaml: `include:
  - project: org/templates
    ref: main
    file: /ci/build.yml`,
			wantHits: 0,
		},
		{
			name: "no include block — safe",
			yaml: `build:
  script:
    - make build`,
			wantHits: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL041.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}

// $CI_COMMIT_SHA is the pipeline's own commit; a partial version moves with
// new releases (#986).
func TestGL041_CommitSHAAndPartialVersions(t *testing.T) {
	for ref, want := range map[string]int{
		"$CI_COMMIT_SHA":   0,
		"${CI_COMMIT_SHA}": 0,
		"1.2.3":            0,
		"v1.2.3-rc.1":      0,
		"1.2":              1,
		"1":                1,
		"v2":               1,
		"main":             1,
	} {
		doc, err := parser.Parse([]byte("include:\n  - component: $CI_SERVER_FQDN/$CI_PROJECT_PATH/build@"+ref+"\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL041.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("@%s: got %d findings, want %d", ref, got, want)
		}
	}
}
