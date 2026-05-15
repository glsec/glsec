package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL036(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{ //nolint:gosec // G101: test case for detecting embedded credentials, not real secrets
			name: "postgres connection string with literal password",
			yaml: `variables:
  DATABASE_URL: "postgres://myapp:s3cr3t@postgres:5432/mydb"`,
			wantHits: 1,
		},
		{ //nolint:gosec // G101: test case for detecting embedded credentials, not real secrets
			name: "elastic URL with literal credentials",
			yaml: `variables:
  ELASTIC_URL: "http://elastic:changeme@elasticsearch:9200"`,
			wantHits: 1,
		},
		{ //nolint:gosec // G101: test case for detecting embedded credentials, not real secrets
			name: "redis URL with literal password",
			yaml: `variables:
  REDIS_URL: "redis://:mypassword@redis:6379/0"`,
			wantHits: 1,
		},
		{
			name: "connection string with variable password — safe",
			yaml: `variables:
  DATABASE_URL: "postgres://myapp:${DB_PASSWORD}@postgres:5432/mydb"`,
			wantHits: 0,
		},
		{ //nolint:gosec // G101: test case for detecting embedded credentials, not real secrets
			name: "connection string with $VAR password — safe",
			yaml: `variables:
  DATABASE_URL: "postgres://myapp:$DB_PASSWORD@postgres:5432/mydb"`,
			wantHits: 0,
		},
		{ //nolint:gosec // G101: test case for detecting embedded credentials, not real secrets
			name: "job-level variable with embedded credentials",
			yaml: `test:
  variables:
    DATABASE_URL: "postgres://ci:password@localhost/testdb"
  script:
    - ./run-tests.sh`,
			wantHits: 1,
		},
		{ //nolint:gosec // G101: test case for detecting embedded credentials, not real secrets
			name: "multiple credential URLs",
			yaml: `variables:
  DATABASE_URL: "postgres://app:secret@db:5432/prod"
  ELASTIC_URL: "http://elastic:changeme@es:9200"`,
			wantHits: 2,
		},
		{
			name: "plain variable without URL — safe",
			yaml: `variables:
  APP_ENV: production
  LOG_LEVEL: debug`,
			wantHits: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL036.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
