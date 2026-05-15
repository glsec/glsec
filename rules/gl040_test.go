package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL040(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "wget with ftp:// URL",
			yaml: `deploy:
  script:
    - wget -q --ftp-user="user" --ftp-password="$FTP_PASSWORD" ftp://ftp.example.com/assets.zip`,
			wantHits: 1,
		},
		{
			name: "curl with ftp:// URL",
			yaml: `deploy:
  script:
    - curl -u "$FTP_USER:$FTP_PASSWORD" ftp://example.com/file.zip`,
			wantHits: 1,
		},
		{
			name: "curl with --ssl-reqd and ftp:// — safe (explicit TLS)",
			yaml: `deploy:
  script:
    - curl --ssl-reqd -u "$FTP_USER:$FTP_PASSWORD" ftp://example.com/file.zip`,
			wantHits: 0,
		},
		{
			name: "ftps:// URL — safe",
			yaml: `deploy:
  script:
    - wget ftps://ftp.example.com/file.zip`,
			wantHits: 0,
		},
		{
			name: "sftp:// URL — safe",
			yaml: `deploy:
  script:
    - curl sftp://example.com/file.zip`,
			wantHits: 0,
		},
		{
			name: "https:// URL — safe",
			yaml: `deploy:
  script:
    - curl https://example.com/file.zip`,
			wantHits: 0,
		},
		{
			name: "multiple ftp:// lines",
			yaml: `deploy:
  script:
    - wget ftp://ftp.example.com/assets.zip
    - wget ftp://ftp.example.com/documents.zip`,
			wantHits: 2,
		},
		{
			name: "ftp:// in before_script",
			yaml: `before_script:
  - wget ftp://files.example.com/config.tar.gz`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL040.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
