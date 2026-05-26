package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
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
		{
			name: "top-level CI_DEBUG_SERVICES true",
			yaml: `variables:
  CI_DEBUG_SERVICES: "true"`,
			wantHits: 1,
		},
		{
			name: "CI_DEBUG_SERVICES unquoted true",
			yaml: `variables:
  CI_DEBUG_SERVICES: true`,
			wantHits: 1,
		},
		{
			name: "CI_DEBUG_SERVICES truthy 1",
			yaml: `variables:
  CI_DEBUG_SERVICES: "1"`,
			wantHits: 1,
		},
		{
			name: "CI_DEBUG_SERVICES false — safe",
			yaml: `variables:
  CI_DEBUG_SERVICES: "false"`,
			wantHits: 0,
		},
		{
			name: "job-level CI_DEBUG_SERVICES true",
			yaml: `e2e:
  variables:
    CI_DEBUG_SERVICES: "true"
  services:
    - postgres:16
  script:
    - ./test.sh`,
			wantHits: 1,
		},
		{
			name: "both debug toggles in one block — two findings",
			yaml: `variables:
  CI_DEBUG_TRACE: "true"
  CI_DEBUG_SERVICES: "true"`,
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

func TestGL033Severity(t *testing.T) {
	doc, err := parser.Parse([]byte(`variables:
  CI_DEBUG_TRACE: "true"
  CI_DEBUG_SERVICES: "true"`), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	want := map[string]finding.Severity{
		"CI_DEBUG_TRACE":    finding.Error,
		"CI_DEBUG_SERVICES": finding.Warn,
	}
	for _, f := range GL033.Check(doc.Root, "test.yml") {
		for varName, sev := range want {
			if strings.Contains(f.Message, varName) && f.Severity != sev {
				t.Errorf("%s: got severity %q, want %q", varName, f.Severity, sev)
			}
		}
	}
}
