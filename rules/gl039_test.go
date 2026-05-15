package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL039(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "npm audit silenced with || true",
			yaml: `security:
  script:
    - npm audit --audit-level=high || true`,
			wantHits: 1,
		},
		{
			name: "composer audit silenced",
			yaml: `security:
  script:
    - composer audit || true`,
			wantHits: 1,
		},
		{
			name: "trivy silenced",
			yaml: `scan:
  script:
    - trivy image myapp:latest || true`,
			wantHits: 1,
		},
		{
			name: "snyk silenced with || exit 0",
			yaml: `security:
  script:
    - snyk test || exit 0`,
			wantHits: 1,
		},
		{
			name: "npm audit without silencing — safe",
			yaml: `security:
  script:
    - npm audit --audit-level=high`,
			wantHits: 0,
		},
		{
			name: "unrelated command silenced — safe",
			yaml: `build:
  script:
    - make lint || true`,
			wantHits: 0,
		},
		{
			name: "multiple tools silenced",
			yaml: `security:
  script:
    - npm audit || true
    - trivy image myapp || true
    - snyk test`,
			wantHits: 2,
		},
		{
			name: "inspector check silenced",
			yaml: `security:
  script:
    - inspector check soup.json || true`,
			wantHits: 1,
		},
		{
			name: "osv-scanner silenced",
			yaml: `security:
  script:
    - osv-scanner --lockfile package-lock.json || true`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL039.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
