package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL032(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "echo key variable to .ssh/ path",
			yaml: `before_script:
  - echo "$DEPLOY_SERVER_PRIVATE_KEY" | tr -d '\r' > ~/.ssh/id_rsa`,
			wantHits: 1,
		},
		{
			name: "echo variable with PRIVATE in name",
			yaml: `before_script:
  - echo "$SSH_PRIVATE_KEY" | tr -d '\r' | ssh-add -`,
			wantHits: 1,
		},
		{
			name: "echo variable with _KEY suffix",
			yaml: `deploy:
  script:
    - echo "$DEPLOY_KEY" > /tmp/key`,
			wantHits: 1,
		},
		{
			name: "ssh-add from stdin without echo to file — counted because var has PRIVATE",
			yaml: `before_script:
  - eval $(ssh-agent -s)
  - echo "$SSH_PRIVATE_KEY" | ssh-add -`,
			wantHits: 1,
		},
		{
			name: "safe ssh-add without echo of key name",
			yaml: `before_script:
  - eval $(ssh-agent -s)
  - ssh-add ~/.ssh/id_rsa`,
			wantHits: 0,
		},
		{
			name: "echo unrelated variable — safe",
			yaml: `build:
  script:
    - echo "$BUILD_VERSION" > version.txt`,
			wantHits: 0,
		},
		{
			name: "echo to .ssh/ path with key content",
			yaml: `before_script:
  - echo "$ID_RSA" > ~/.ssh/id_rsa
  - chmod 600 ~/.ssh/id_rsa`,
			wantHits: 1,
		},
		{
			name: "echo StrictHostKeyChecking into ~/.ssh/config — config, not a key",
			yaml: `before_script:
  - mkdir -p ~/.ssh
  - echo "StrictHostKeyChecking no" >> ~/.ssh/config`,
			wantHits: 0,
		},
		{
			name: "echo into ~/.ssh/known_hosts — not a key",
			yaml: `before_script:
  - ssh-keyscan gitlab.com >> ~/.ssh/known_hosts
  - echo "gitlab.com ssh-rsa AAAA..." >> ~/.ssh/known_hosts`,
			wantHits: 0,
		},
		{
			name: "echo key variable redirected into ~/.ssh/config still flagged",
			yaml: `before_script:
  - echo "$SSH_PRIVATE_KEY" >> ~/.ssh/config`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL032.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
