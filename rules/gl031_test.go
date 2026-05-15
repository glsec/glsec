package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL031(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "top-level DOCKER_TLS_CERTDIR empty string",
			yaml: `variables:
  DOCKER_HOST: tcp://docker:2375
  DOCKER_TLS_CERTDIR: ""`,
			wantHits: 1,
		},
		{
			name: "job-level DOCKER_TLS_CERTDIR empty string",
			yaml: `build:
  services:
    - docker:dind
  variables:
    DOCKER_TLS_CERTDIR: ""
  script:
    - docker build .`,
			wantHits: 1,
		},
		{
			name: "DOCKER_TLS_CERTDIR set to /certs — safe",
			yaml: `variables:
  DOCKER_TLS_CERTDIR: "/certs"`,
			wantHits: 0,
		},
		{
			name: "no DOCKER_TLS_CERTDIR — safe",
			yaml: `variables:
  SOME_VAR: "value"`,
			wantHits: 0,
		},
		{
			name: "top-level and job-level both empty — two findings",
			yaml: `variables:
  DOCKER_TLS_CERTDIR: ""
build:
  variables:
    DOCKER_TLS_CERTDIR: ""
  script:
    - docker build .`,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL031.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
