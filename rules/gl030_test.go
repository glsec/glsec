package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL030(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "ssh-keyscan in before_script",
			yaml: `before_script:
  - mkdir -p ~/.ssh
  - ssh-keyscan -H 'deploy.example.com' >> ~/.ssh/known_hosts`,
			wantHits: 1,
		},
		{
			name: "ssh-keyscan in job script",
			yaml: `deploy:
  script:
    - ssh-keyscan example.com >> ~/.ssh/known_hosts
    - ssh user@example.com "deploy.sh"`,
			wantHits: 1,
		},
		{
			name: "known_hosts from variable — safe",
			yaml: `before_script:
  - mkdir -p ~/.ssh
  - echo "$SSH_KNOWN_HOSTS" >> ~/.ssh/known_hosts
  - chmod 644 ~/.ssh/known_hosts`,
			wantHits: 0,
		},
		{
			name: "no SSH commands — safe",
			yaml: `build:
  script:
    - make build`,
			wantHits: 0,
		},
		{
			name: "ssh-keyscan in top-level and job — two findings",
			yaml: `before_script:
  - ssh-keyscan host1.example.com >> ~/.ssh/known_hosts
deploy:
  script:
    - ssh-keyscan host2.example.com >> ~/.ssh/known_hosts`,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL030.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
