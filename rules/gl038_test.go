package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL038(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "sqlcmd -P with quoted literal",
			yaml: `job:
  script:
    - sqlcmd -S localhost -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "sqlcmd -P with variable — safe",
			yaml: `job:
  script:
    - sqlcmd -S localhost -U SA -P "$MSSQL_PASSWORD" -Q "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -p with literal",
			yaml: `job:
  script:
    - mysql -u root -pExampleP4ss! -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mysql --password= with literal",
			yaml: `job:
  script:
    - mysqldump --password=ExampleP4ss! mydb > dump.sql`,
			wantHits: 1,
		},
		{
			name: "mysql --password= with variable — safe",
			yaml: `job:
  script:
    - mysql --password=$DB_PASSWORD -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "PGPASSWORD with literal",
			yaml: `job:
  script:
    - PGPASSWORD=ExampleP4ss! psql -U admin -c "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "PGPASSWORD with variable — safe",
			yaml: `job:
  script:
    - PGPASSWORD=$DB_PASSWORD psql -U admin -c "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mongosh --password with literal",
			yaml: `job:
  script:
    - mongosh --username admin --password ExampleP4ss! mydb`,
			wantHits: 1,
		},
		{
			name: "sed URL rewrite with hardcoded password",
			yaml: `job:
  script:
    - sed -i "s/sa:[^@]*@/sa:ExampleP4ss!@/" .env`,
			wantHits: 1,
		},
		{
			name: "sed URL rewrite with variable — safe",
			yaml: `job:
  script:
    - sed -i "s/sa:[^@]*@/sa:${DB_PASS}@/" .env`,
			wantHits: 0,
		},
		{
			name: "multiple violations in one job",
			yaml: `job:
  script:
    - sqlcmd -P "ExampleP4ss!" -Q "SELECT 1"
    - mysql -pExampleP4ss!`,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL038.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}
