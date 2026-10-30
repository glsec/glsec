// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// Test values are built at run time, so this file holds no token a secret
// scanner would report.
var ghp = "ghp_" + strings.Repeat("aB3", 12)

func TestString(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`  GH: "` + ghp + `"`, `  GH: "ghp_` + strings.Repeat("*", 36) + `"`},
		{`curl -fsSL https://user:hunter2pass@example.com/install.sh | bash`, `curl -fsSL https://user:***********@example.com/install.sh | bash`},
		{`curl -u admin:S3cr3tPassw0rd https://api.example.com`, `curl -u admin:************** https://api.example.com`},
		{`curl -H "Authorization: Bearer a8f3k2l9q0w7" x`, `curl -H "Authorization: Bearer ************" x`},
		{`curl --header "PRIVATE-TOKEN: abcdefghij" x`, `curl --header "PRIVATE-TOKEN: **********" x`},
		{`docker login -u ci --password s3cretvalue reg`, `docker login -u ci --password *********** reg`},
		{`export DB_PASSWORD=S3cr3tPassw0rd`, `export DB_PASSWORD=**************`},
		{`  DEPLOY_TOKEN: "k8s9d7f6g5h4j3"`, `  DEPLOY_TOKEN: "**************"`},

		// stay as they are
		{`curl -u "$API_USER:$API_PASSWORD" https://api.example.com`, ``},
		{`curl -H "Authorization: Bearer $TOKEN" https://api.example.com`, ``},
		{`git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.com/g/p.git`, ``},
		{`export DB_PASSWORD=$DB_PASSWORD`, ``},
		{`docker login --password-stdin registry.example.com`, ``},
		{`docker run -u 1000:1000 alpine:3.20.3`, ``},
		{`image: node:20.11.0`, ``},
	} {
		want := tc.want
		if want == "" {
			want = tc.in
		}
		got := String(tc.in)
		if got != want {
			t.Errorf("String(%q)\n got %q\nwant %q", tc.in, got, want)
		}
		if len(got) != len(tc.in) {
			t.Errorf("String(%q) changed the length: %d, was %d", tc.in, len(got), len(tc.in))
		}
		if again := String(got); again != got {
			t.Errorf("masking twice changed %q to %q", got, again)
		}
	}
}

func TestFindings(t *testing.T) {
	in := []finding.Finding{{RuleID: "GL011", Message: "pipes https://u:pw12345678@example.com into bash", Line: 3, Col: 7}}
	out := Findings(in)
	if strings.Contains(out[0].Message, "pw12345678") || out[0].Line != 3 || out[0].Col != 7 {
		t.Errorf("Findings = %+v", out[0])
	}
	if in[0].Message != "pipes https://u:pw12345678@example.com into bash" {
		t.Error("Findings must not change its input")
	}
}
