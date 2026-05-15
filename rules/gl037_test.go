package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL037(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "trigger job without inherit: variables: false and secret top-level var",
			yaml: `variables:
  DEPLOY_TOKEN: $DEPLOY_TOKEN

deploy:
  trigger:
    project: myorg/k8s-deployer
    branch: main`,
			wantHits: 1,
		},
		{
			name: "trigger job with inherit: variables: false — safe",
			yaml: `variables:
  DEPLOY_TOKEN: $DEPLOY_TOKEN

deploy:
  trigger:
    project: myorg/k8s-deployer
  inherit:
    variables: false`,
			wantHits: 0,
		},
		{
			name: "trigger job but no secret top-level vars — safe",
			yaml: `variables:
  APP_ENV: production
  LOG_LEVEL: debug

deploy:
  trigger:
    project: myorg/k8s-deployer`,
			wantHits: 0,
		},
		{
			name: "no top-level variables at all — safe",
			yaml: `deploy:
  trigger:
    project: myorg/k8s-deployer`,
			wantHits: 0,
		},
		{
			name: "two trigger jobs both missing inherit: variables: false",
			yaml: `variables:
  API_KEY: $API_KEY

child-a:
  trigger:
    include:
      - local: .gitlab/ci/a.yml
child-b:
  trigger:
    include:
      - local: .gitlab/ci/b.yml`,
			wantHits: 2,
		},
		{
			name: "inherit block present but variables not false",
			yaml: `variables:
  DB_PASSWORD: $DB_PASSWORD

deploy:
  trigger:
    project: myorg/deployer
  inherit:
    default: false`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL037.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
