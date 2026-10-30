// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings070(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL070.Check(doc.Root, "test.yml")
}

func TestGL070_Flagged(t *testing.T) {
	flagged := []string{
		`gcloud auth activate-service-account --key-file "$GCP_KEY"`,
		`gcloud auth activate-service-account --key-file=/tmp/key.json`,
		`aws configure set aws_secret_access_key "$AWS_SECRET"`,
		`export AWS_SECRET_ACCESS_KEY="$AWS_SECRET"`,
		`az login --service-principal -u app --password "$SECRET" --tenant t`,
	}
	for _, line := range flagged {
		f := findings070(t, "job:\n  script:\n    - '"+escapeSingle(line)+"'\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %q, got %d", line, len(f))
			continue
		}
		if f[0].RuleID != "GL070" || f[0].Severity != finding.Warn {
			t.Errorf("unexpected finding for %q: %+v", line, f[0])
		}
	}
}

func TestGL070_NotFlagged_Keyless(t *testing.T) {
	clean := []string{
		`gcloud auth login --cred-file=/tmp/wif.json`,                  // keyless WIF
		`az login --service-principal -u app --federated-token "$TOK"`, // keyless OIDC
		`aws sts assume-role-with-web-identity --role-arn arn`,         // keyless
		`gcloud config set project my-project`,                         // unrelated
		`# gcloud auth activate-service-account --key-file x`,          // comment
	}
	for _, line := range clean {
		if f := findings070(t, "job:\n  script:\n    - '"+escapeSingle(line)+"'\n"); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d: %+v", line, len(f), f)
		}
	}
}

func TestGL070_STSCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"assume-role-with-web-identity in one line", `
deploy:
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://gitlab.example.com
  script:
    - >
      export $(printf "AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s"
      $(aws sts assume-role-with-web-identity --role-arn $ROLE --role-session-name ci
      --web-identity-token "$GITLAB_OIDC_TOKEN" --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text))
`, 0},
		{"STS output in an earlier line", `
deploy:
  script:
    - CREDS=$(aws sts assume-role --role-arn $ROLE --role-session-name ci)
    - export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .Credentials.SecretAccessKey)
`, 0},
		{"static key in another job", `
sts:
  script:
    - CREDS=$(aws sts assume-role --role-arn $ROLE --role-session-name ci)
static:
  script:
    - export AWS_SECRET_ACCESS_KEY=$PROD_SECRET
`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.yaml), "t.yml")
			if err != nil {
				t.Fatal(err)
			}
			if f := GL070.Check(doc.Root, "t.yml"); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d", tc.want, len(f))
			}
		})
	}
}

// AWS_SECRET_ACCESS_KEY= counts as an assignment, not as text inside an
// argument (#998).
func TestGL070_AssignmentOnly(t *testing.T) {
	for line, want := range map[string]int{
		`curl --request POST --form "AWS_SECRET_ACCESS_KEY=$OTHER_SECRET" https://hooks.example.com/build`: 0,
		`echo '{"AWS_SECRET_ACCESS_KEY=": 1}' > x.json`:                                                    0,
		`export AWS_SECRET_ACCESS_KEY=$PROD_SECRET`:                                                        1,
		`AWS_SECRET_ACCESS_KEY=$S aws s3 ls`:                                                               1,
		`AWS_ACCESS_KEY_ID=$I AWS_SECRET_ACCESS_KEY=$S aws s3 ls`:                                          1,
		`env AWS_SECRET_ACCESS_KEY=$S terraform apply`:                                                     1,
		`cd infra && AWS_SECRET_ACCESS_KEY=$S terraform apply`:                                             1,
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - '"+strings.ReplaceAll(line, "'", "''")+"'\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL070.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("%s: got %d findings, want %d", line, got, want)
		}
	}
}
