// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
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
		{
			name: "public key variable — not a private key",
			yaml: `before_script:
  - echo "extra-trusted-public-keys = $ATTIC_PUBLIC_KEY" >> /etc/nix/nix.conf`,
			wantHits: 0,
		},
		{
			name: "host key into known_hosts via variable-name branch",
			yaml: `before_script:
  - echo "${SSH_HOST_KEY}" > ~/.ssh/known_hosts`,
			wantHits: 0,
		},
		{
			name: "public key written to authorized_keys",
			yaml: `before_script:
  - echo "${PUBLIC_KEY}" > ~/.ssh/authorized_keys`,
			wantHits: 0,
		},
		{
			name: "private key still flagged alongside public key on same line",
			yaml: `before_script:
  - echo "${PRIVATE_KEY}" > ~/.ssh/id_rsa && echo "${PUBLIC_KEY}" > ~/.ssh/authorized_keys`,
			wantHits: 1,
		},
		{ //nolint:gosec // G101: non-SSH credential, test of generalized detection
			name: "non-SSH key variable (GCP) flagged via generalized message",
			yaml: `deploy:
  script:
    - echo "$GCP_SERVICE_ACCOUNT_KEY" | base64 -d > /tmp/gcloud-key.json`,
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

// Only a key that is written counts, and a write into a key file only when
// it carries a variable (#993).
func TestGL032_WrittenKeysOnly(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{`echo "toolchain cache fresh ($CURRENT_KEY)"`, 0},
		{`printf '\n' >> ~/.ssh/id_ed25519`, 0},
		{`echo "$SSH_PRIVATE_KEY" | ssh-add -`, 1},
		{`echo "$SSH_PRIVATE_KEY" > ~/.ssh/id_rsa`, 1},
		{`echo "$DEPLOY_KEY" | base64 -d > ~/.ssh/id_ed25519`, 1},
		{`ssh-add <(echo "$SSH_PRIVATE_KEY")`, 1},
		{`{ echo "$GPG_PRIVATE_KEY"; } | gpg --batch --import`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - "+strconv.Quote(tc.line)+"\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL032.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.line, got, tc.want)
		}
	}
}
