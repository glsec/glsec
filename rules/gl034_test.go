package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL034(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "trigger mapping without strategy: depend",
			yaml: `run-security-scan:
  stage: test
  trigger:
    include:
      - local: .gitlab/ci/security.gitlab-ci.yml`,
			wantHits: 1,
		},
		{
			name: "trigger mapping with strategy: depend — safe",
			yaml: `run-security-scan:
  stage: test
  trigger:
    include:
      - local: .gitlab/ci/security.gitlab-ci.yml
    strategy: depend`,
			wantHits: 0,
		},
		{
			name: "scalar trigger without strategy",
			yaml: `downstream:
  trigger: other/project`,
			wantHits: 1,
		},
		{
			name: "trigger with project key but no strategy",
			yaml: `downstream:
  trigger:
    project: other/project
    branch: main`,
			wantHits: 1,
		},
		{
			name: "trigger with project and strategy: depend — safe",
			yaml: `downstream:
  trigger:
    project: other/project
    strategy: depend`,
			wantHits: 0,
		},
		{
			name: "no trigger job — safe",
			yaml: `build:
  script:
    - make build`,
			wantHits: 0,
		},
		{
			name: "two trigger jobs both missing strategy",
			yaml: `child-a:
  trigger:
    include:
      - local: .gitlab/ci/a.yml
child-b:
  trigger:
    include:
      - local: .gitlab/ci/b.yml`,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL034.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
