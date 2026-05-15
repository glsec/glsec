package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL029(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "docker login with -p flag",
			yaml: `deploy:
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY`,
			wantHits: 1,
		},
		{
			name: "docker login with --password-stdin — safe",
			yaml: `deploy:
  script:
    - echo "$CI_REGISTRY_PASSWORD" | docker login --password-stdin -u $CI_REGISTRY_USER $CI_REGISTRY`,
			wantHits: 0,
		},
		{
			name: "docker login without password flag — safe",
			yaml: `deploy:
  script:
    - docker login $CI_REGISTRY`,
			wantHits: 0,
		},
		{
			name: "unrelated docker command — safe",
			yaml: `build:
  script:
    - docker build -t myimage .`,
			wantHits: 0,
		},
		{
			name: "-p in before_script",
			yaml: `before_script:
  - docker login -u user -p pass registry.example.com`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL029.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
