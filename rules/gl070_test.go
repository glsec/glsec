package rules

import (
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
