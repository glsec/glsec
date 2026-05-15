package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL042(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "curl -k",
			yaml: `build:
  script:
    - curl -k https://internal.example.com/artifact.tar.gz`,
			wantHits: 1,
		},
		{
			name: "curl --insecure",
			yaml: `build:
  script:
    - curl --insecure https://internal.example.com/artifact.tar.gz`,
			wantHits: 1,
		},
		{
			name: "wget --no-check-certificate",
			yaml: `build:
  script:
    - wget --no-check-certificate https://internal.example.com/file.zip`,
			wantHits: 1,
		},
		{
			name: "git with http.sslVerify=false",
			yaml: `build:
  script:
    - git -c http.sslVerify=false clone https://gitlab.example.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "npm --strict-ssl=false",
			yaml: `build:
  script:
    - npm install --strict-ssl=false`,
			wantHits: 1,
		},
		{
			name: "npm config set strict-ssl false",
			yaml: `build:
  script:
    - npm config set strict-ssl false
    - npm install`,
			wantHits: 1,
		},
		{
			name: "GIT_SSL_NO_VERIFY inline in script",
			yaml: `build:
  script:
    - GIT_SSL_NO_VERIFY=true git clone https://gitlab.example.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "GIT_SSL_NO_VERIFY in variables block",
			yaml: `variables:
  GIT_SSL_NO_VERIFY: "true"

build:
  script:
    - git clone https://gitlab.example.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "GIT_SSL_NO_VERIFY in job variables",
			yaml: `build:
  variables:
    GIT_SSL_NO_VERIFY: "1"
  script:
    - git clone https://gitlab.example.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "curl without -k — safe",
			yaml: `build:
  script:
    - curl https://example.com/file.tar.gz`,
			wantHits: 0,
		},
		{
			name: "curl with --cacert — safe",
			yaml: `build:
  script:
    - curl --cacert /etc/ssl/certs/internal-ca.crt https://internal.example.com/file`,
			wantHits: 0,
		},
		{
			name: "wget without --no-check-certificate — safe",
			yaml: `build:
  script:
    - wget https://example.com/file.zip`,
			wantHits: 0,
		},
		{
			name: "multiple violations",
			yaml: `build:
  script:
    - curl -k https://internal.example.com/a.tar.gz
    - wget --no-check-certificate https://internal.example.com/b.zip`,
			wantHits: 2,
		},
		{
			name: "before_script at top level",
			yaml: `before_script:
  - curl -k https://internal.example.com/setup.sh | bash`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL042.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
