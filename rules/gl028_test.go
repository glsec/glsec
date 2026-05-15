package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL028(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "untracked true without restriction",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true`,
			wantHits: 1,
		},
		{
			name: "untracked true with paths — safe",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    paths:
      - dist/`,
			wantHits: 0,
		},
		{
			name: "untracked true with exclude — safe",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
    exclude:
      - "**/.env"
      - "**/*.key"`,
			wantHits: 0,
		},
		{
			name: "untracked false — safe",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: false`,
			wantHits: 0,
		},
		{
			name: "no artifacts block — safe",
			yaml: `build:
  script:
    - make build`,
			wantHits: 0,
		},
		{
			name: "multiple jobs — only one flagged",
			yaml: `build:
  script:
    - make build
  artifacts:
    untracked: true
test:
  script:
    - make test
  artifacts:
    untracked: true
    paths:
      - reports/`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL028.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
