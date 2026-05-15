package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL033(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "top-level CI_DEBUG_TRACE true",
			yaml: `variables:
  CI_DEBUG_TRACE: "true"`,
			wantHits: 1,
		},
		{
			name: "job-level CI_DEBUG_TRACE true",
			yaml: `deploy:
  variables:
    CI_DEBUG_TRACE: "true"
  script:
    - ./deploy.sh`,
			wantHits: 1,
		},
		{
			name: "CI_DEBUG_TRACE false — safe",
			yaml: `variables:
  CI_DEBUG_TRACE: "false"`,
			wantHits: 0,
		},
		{
			name: "no CI_DEBUG_TRACE — safe",
			yaml: `variables:
  SOME_VAR: "value"`,
			wantHits: 0,
		},
		{
			name: "CI_DEBUG_TRACE in top-level and job — two findings",
			yaml: `variables:
  CI_DEBUG_TRACE: "true"
deploy:
  variables:
    CI_DEBUG_TRACE: "true"
  script:
    - ./deploy.sh`,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL033.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
