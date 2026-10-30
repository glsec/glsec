// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
)

// A finding inside a `|` block is reported on the line of its command, not
// on the `- |` line (#974). Each command is the third line of its block, on
// line 8 of the file.
func TestScriptRulesReportTheLineInsideABlock(t *testing.T) {
	for _, tc := range []struct {
		rule    rule.Rule
		command string
	}{
		{GL026, "git clone https://example.com/lib.git"},
		{GL030, "ssh-keyscan example.com >> ~/.ssh/known_hosts"},
		{GL035, "git push https://user:$TOKEN@example.com/group/project.git"},
		{GL042, "curl -k https://example.com/install.sh -o install.sh"},
		{GL044, `git checkout "$CI_MERGE_REQUEST_SOURCE_BRANCH_SHA"`},
		{GL048, "ssh -o StrictHostKeyChecking=no deploy@example.com"},
		{GL056, "docker run --privileged example/img"},
		{GL057, "docker run --cap-add SYS_ADMIN example/img"},
		{GL058, "docker run --network host example/img"},
		{GL059, "docker build --build-arg NPM_TOKEN=$NPM_TOKEN ."},
		{GL060, "docker run -v /var/run/docker.sock:/var/run/docker.sock example/img"},
		{GL061, "docker run --pid host example/img"},
		{GL063, "chmod 777 out"},
		{GL068, "set -x"},
		{GL069, "apt-get install -y --allow-unauthenticated pkg"},
		{GL070, `echo "AWS_SECRET_ACCESS_KEY=$AWS_SECRET" > .env`},
		{GL076, "docker run --security-opt seccomp=unconfined example/img"},
		{GL077, "docker run --ipc host example/img"},
	} {
		t.Run(tc.rule.ID(), func(t *testing.T) {
			src := "build:\n  image: docker:27.3.1\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n  script:\n    - |\n      echo one\n      " + tc.command + "\n      echo two\n"
			doc, err := parser.Parse([]byte(src), "test.yml")
			if err != nil {
				t.Fatal(err)
			}
			got := Check(tc.rule, doc, "test.yml")
			if len(got) == 0 {
				t.Fatalf("no finding for %q", tc.command)
			}
			for _, f := range got {
				if f.Line != 8 {
					t.Errorf("finding on line %d, want 8 (the command's line): %s", f.Line, f.Message)
				}
				if f.Col != 0 {
					t.Errorf("column %d, want 0 inside a block", f.Col)
				}
			}
		})
	}
}
