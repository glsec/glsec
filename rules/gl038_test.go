// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
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
			name: "sqlcmd -P with quoted literal to localhost without services — still flagged (#800)",
			yaml: `job:
  script:
    - sqlcmd -S localhost -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "sqlcmd -P with quoted literal to localhost with services — no finding (#800)",
			yaml: `job:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - sqlcmd -S localhost -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -h localhost with services from default — no finding (#800)",
			yaml: `default:
  services:
    - name: mysql:8.0
      alias: mysql
job:
  script:
    - mysql -h localhost -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "sqlcmd -P with quoted literal to external host",
			yaml: `job:
  script:
    - sqlcmd -S db.example.com -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mysqladmin ping to own service alias — no finding (#800)",
			yaml: `integration:mysql:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - mysqladmin ping -h mysql -uroot -pci-only --silent`,
			wantHits: 0,
		},
		{
			name: "sqlcmd to own service alias — no finding (#800)",
			yaml: `integration:mssql:
  services:
    - name: mcr.microsoft.com/mssql/server:2022-latest
      alias: mssql
  script:
    - sqlcmd -S mssql -U SA -P "ExampleP4ss!" -Q "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -h names another job's service, not this job's — still flagged",
			yaml: `integration:mysql:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - echo ok
integration:mssql:
  services:
    - name: mcr.microsoft.com/mssql/server:2022-latest
      alias: mssql
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mysql --host= names a service by image name, no alias — no finding",
			yaml: `job:
  services:
    - postgres:16
  script:
    - mysql --host=postgres -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "psql PGHOST names own service alias — no finding",
			yaml: `job:
  services:
    - name: postgres:16
      alias: pg
  script:
    - PGHOST=pg PGPASSWORD=ExampleP4ss! psql -U admin -c "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "psql to external host — still flagged",
			yaml: `job:
  script:
    - PGPASSWORD=ExampleP4ss! psql -h db.example.com -U admin -c "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mongosh --host names own service alias — no finding",
			yaml: `job:
  services:
    - name: mongo:7
      alias: mongo
  script:
    - mongosh --host mongo --username admin --password ExampleP4ss! mydb`,
			wantHits: 0,
		},
		{
			name: "mixed local and external hosts in one item — still flagged",
			yaml: `job:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1" && mysql -h db.example.com -u root -pOtherP4ss! -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "docker login literal is not suppressed by services",
			yaml: `job:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - docker login -u user -p ExampleP4ss! registry.example.com`,
			wantHits: 1,
		},
		{
			name: "service inherited through extends — no finding",
			yaml: `.db:
  services:
    - name: mysql:8.0
      alias: mysql
job:
  extends: .db
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "service from default — no finding",
			yaml: `default:
  services:
    - name: mysql:8.0
      alias: mysql
job:
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "127.0.0.1 target without services — still flagged",
			yaml: `job:
  script:
    - mysql -h 127.0.0.1 -u root -pci-only -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "127.0.0.1 target with services — no finding",
			yaml: `job:
  services:
    - name: mysql:8.0
      alias: mysql
  script:
    - mysql -h 127.0.0.1 -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -h bare name of a namespaced service — still flagged (#800)",
			yaml: `job:
  services:
    - registry.example.com/team/mysql:8.0
  script:
    - mysql -h mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 1,
		},
		{
			name: "mysql -h double-underscore hostname of a namespaced service — no finding (#800)",
			yaml: `job:
  services:
    - registry.example.com/team/mysql:8.0
  script:
    - mysql -h registry.example.com__team__mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
		},
		{
			name: "mysql -h hyphen hostname of a namespaced service — no finding (#800)",
			yaml: `job:
  services:
    - registry.example.com/team/mysql:8.0
  script:
    - mysql -h registry.example.com-team-mysql -u root -pci-only -e "SELECT 1"`,
			wantHits: 0,
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

// curl -u, an Authorization header and an assignment to a secret-like name
// with a literal (#910).
func TestGL038_CurlAuthAndAssignments(t *testing.T) {
	for _, tc := range []struct {
		line string
		want string // tool in the message, "" for no finding
	}{
		{`curl -u admin:S3cr3tPassw0rd https://api.example.com`, "curl -u"},
		{`curl --user=admin:S3cr3tPassw0rd https://api.example.com`, "curl -u"},
		{`curl -sf -u 'deploy:Hunter2Hunter2' https://api.example.com`, "curl -u"},
		{`curl -u admin:$API_PASSWORD https://api.example.com`, ""},
		{`curl -u "$API_USER:${API_PASSWORD}" https://api.example.com`, ""},
		{`curl -u admin: https://api.example.com`, ""},
		{`curl -u : --negotiate https://api.example.com`, ""},
		{`curl -u admin:changeme https://api.example.com`, ""},

		{`curl -H "Authorization: Bearer a8f3k2l9q0w7e6r5t4y3u2i1o0p9" https://api.example.com`, "Authorization header"},
		{`wget --header="Authorization: Token a8f3k2l9q0w7e6r5t4" https://api.example.com`, "Authorization header"},
		{`curl --header 'authorization: basic YWRtaW46czNjcjN0' https://api.example.com`, "Authorization header"},
		{`curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com`, ""},
		{`curl -H "Authorization: Bearer ${API_TOKEN}" https://api.example.com`, ""},
		{`curl -H "Authorization: Bearer <token>" https://api.example.com`, ""},
		{`curl -H "Authorization: Bearer your-token-here" https://api.example.com`, ""},

		{`export OKTA_API_TOKEN=00aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd`, "export"},
		{`DB_PASSWORD=S3cr3tPassw0rd ./migrate.sh`, "export"},
		{`set -e; export SERVICE_SECRET="k8s9d7f6g5h4j3"`, "export"},
		{`export OKTA_API_TOKEN=$OKTA_TOKEN`, ""},
		{`export OKTA_API_TOKEN="${OKTA_TOKEN}"`, ""},
		{`export DEPLOY_TOKEN=$(cat /run/secrets/token)`, ""},
		{`export DB_PASSWORD=changeme123`, ""},
		{`export MYSQL_ROOT_PASSWORD=root`, ""},
		{`export POSTGRES_PASSWORD=postgres`, ""},
		{`export SSH_KEY=~/.ssh/id_ed25519`, ""},
		{`export GOOGLE_CREDENTIAL=/tmp/sa.json`, ""},
		{`export BUILD_NUMBER=12345678`, ""},
		{`docker build --build-arg API_KEY=a8f3k2l9q0w7e6 .`, ""},
		{`COVERAGE_KEY=ruby-32-pg-coverage bundle exec rake`, ""},
		{`export TEST_SECRET=test_secret_value`, ""},
		{`APP_SECRET_KEY=Local-only-ci-instance-secret! ./run`, ""},
		{`export API_TOKEN=1-a8f3k2l9q0w7e6r5t4y3u2i1o0p9`, "export"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			doc, err := parser.Parse([]byte("job:\n  script:\n    - '"+strings.ReplaceAll(tc.line, "'", "''")+"'\n"), "test.yml")
			if err != nil {
				t.Fatal(err)
			}
			got := GL038.Check(doc.Root, "test.yml")
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected no finding, got %v", got)
				}
				return
			}
			if len(got) != 1 || !strings.HasPrefix(got[0].Message, "["+tc.want+"]") {
				t.Fatalf("expected one [%s] finding, got %v", tc.want, got)
			}
		})
	}
}

// The finding goes on the line with the credential, also inside a multi-line
// script item (#800, part 2).
func TestGL038_LineOfTheCredential(t *testing.T) {
	src := `integration:
  script:
    - for i in $(seq 1 30); do
        mysql -h db.example.com -uroot -pci-only -e 'select 1' && break;
        sleep 2;
      done
    - |
      echo start
      curl -u admin:S3cr3tPassw0rd https://api.example.com
    - >
      echo start

      export SERVICE_SECRET="k8s9d7f6g5h4j3"
    - "echo \"start\"

      docker login -u ci -p Hunter2Hunter2 registry.example.com"
`
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, f := range GL038.Check(doc.Root, "test.yml") {
		lines = append(lines, f.Line)
	}
	// The quoted item has an escape, so its lines can't be traced and the
	// finding stays where the item starts.
	want := []int{4, 9, 13, 14}
	if len(lines) != len(want) {
		t.Fatalf("lines = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("lines = %v, want %v", lines, want)
			break
		}
	}
}

// A database client and its -p flag must be in the same command: a word
// mysql and a later -print are not a password (#985).
func TestGL038_ClientAndFlagInOneCommand(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{`for pkg in core mysql mail; do find deb/ -name "app-${pkg}_*.deb" -print; done`, 0},
		{`echo mysql; ls -p /tmp`, 0},
		{`mysql -h db.example.com -uroot -pS3cret -e "select 1"`, 1},
		{`docker exec -i db mysql -h db.example.com -uroot -pS3cret`, 1},
		{`sqlcmd -S db.example.com -U sa -P S3cret -Q "select 1"`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - '"+tc.line+"'\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL038.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.line, got, tc.want)
		}
	}
}
