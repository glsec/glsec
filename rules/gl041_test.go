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
			name: "component with two-segment semver — safe",
			yaml: `include:
  - component: gitlab.com/org/security-scan/sast@2.1`,
			wantHits: 0,
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
