package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL035(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "git push with embedded token",
			yaml: `deploy:
  script:
    - git push https://ci:${TRANSLATION_TOKEN}@gitlab.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "git clone with embedded credentials",
			yaml: `build:
  script:
    - git clone https://user:password@github.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "git fetch with embedded token",
			yaml: `sync:
  script:
    - git fetch https://oauth2:$ACCESS_TOKEN@gitlab.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "git remote set-url with embedded token",
			yaml: `deploy:
  script:
    - git remote set-url origin https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git`,
			wantHits: 1,
		},
		{
			name: "git push without credentials — safe",
			yaml: `deploy:
  script:
    - git push origin HEAD:main`,
			wantHits: 0,
		},
		{
			name: "git clone with SSH URL — safe",
			yaml: `build:
  script:
    - git clone git@github.com:org/repo.git`,
			wantHits: 0,
		},
		{
			name: "unrelated https URL — safe",
			yaml: `build:
  script:
    - curl https://user:pass@api.example.com/endpoint`,
			wantHits: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL035.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
