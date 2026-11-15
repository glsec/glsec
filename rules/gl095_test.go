// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings095(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL095.Check(doc.Root, "test.yml")
}

// one095 wraps the command in a single-quoted YAML scalar so a shell `-H
// "Header: value"` colon does not make YAML read the script line as a mapping;
// that is exactly how an author writes such a line in a real pipeline.
func one095(t *testing.T, line string) finding.Finding {
	t.Helper()
	f := findings095(t, "j:\n  script:\n    - '"+line+"'\n")
	if len(f) != 1 {
		t.Fatalf("expected exactly one GL095 finding for %q, got %d: %+v", line, len(f), f)
	}
	return f[0]
}

// Retrieving a credential (IMDS credential path, or the Kubernetes token file)
// is an error.
func TestGL095_CredentialAccessIsError(t *testing.T) {
	for _, line := range []string{
		`curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ci-role`,
		`curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60"`,
		`curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`,
		`curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01" -H Metadata:true`,
		`cat /var/run/secrets/kubernetes.io/serviceaccount/token`,
		`TOKEN=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/role)`,
	} {
		t.Run(line, func(t *testing.T) {
			f := one095(t, line)
			if f.Severity != finding.Error {
				t.Errorf("got severity %v, want error for %q", f.Severity, line)
			}
		})
	}
}

// Reaching the metadata host for facts (region, project id) without a credential
// path is a warn with the same advice.
func TestGL095_MetadataHostIsWarn(t *testing.T) {
	for _, line := range []string{
		`curl -s http://169.254.169.254/latest/meta-data/placement/region`,
		`curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id`,
	} {
		t.Run(line, func(t *testing.T) {
			f := one095(t, line)
			if f.Severity != finding.Warn {
				t.Errorf("got severity %v, want warn for %q", f.Severity, line)
			}
			if !strings.Contains(f.Message, "metadata service") {
				t.Errorf("unexpected message %q", f.Message)
			}
		})
	}
}

func TestGL095_NoFinding(t *testing.T) {
	for _, line := range []string{
		`echo "see http://169.254.169.254 for the metadata docs"`,                      // prose, quote-masked
		`printf 'metadata.google.internal\n'`,                                          // prose
		`# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role`, // comment
		`curl -s http://169.254.1.1/health`,                                            // unrelated link-local service, not the metadata IP
		`curl -s https://metadata.example.com/v1/info`,                                 // a host that only looks similar
		`aws sts get-caller-identity`,                                                  // uses creds, does not read the metadata service
	} {
		t.Run(line, func(t *testing.T) {
			f := findings095(t, "j:\n  script:\n    - "+line+"\n")
			if len(f) != 0 {
				t.Fatalf("expected no GL095 finding for %q, got %+v", line, f)
			}
		})
	}
}

// A line that reaches the metadata host and also hits a credential path is one
// error, not a warn plus an error.
func TestGL095_CredentialWinsOverHost(t *testing.T) {
	f := one095(t, `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/role`)
	if f.Severity != finding.Error {
		t.Errorf("got %v, want a single error", f.Severity)
	}
}

func TestGL095_PositionAndJob(t *testing.T) {
	f := findings095(t, "deploy:\n  script:\n    - make build\n    - cat /var/run/secrets/kubernetes.io/serviceaccount/token\n")
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	if f[0].Job != "deploy" || f[0].Line != 4 {
		t.Errorf("got job %q line %d, want deploy line 4", f[0].Job, f[0].Line)
	}
	if f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "service-account token") {
		t.Errorf("unexpected finding %+v", f[0])
	}
}
