// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// Parts of a finding have to come from one command, not from different lines
// of a block (#759). Each case is a script block and the expected lines.
func TestPerCommandMatching(t *testing.T) {
	rules := map[string]interface {
		Check(doc *yaml.Node, file string) []finding.Finding
	}{"GL011": GL011, "GL015": GL015, "GL016": GL016, "GL021": GL021, "GL025": GL025, "GL032": GL032}
	for _, tc := range []struct {
		name, rule, block string
		lines             []int
	}{
		{"GL011 curl and a -c pipe on different lines", "GL011", "apt-get install -y curl jq\nBODY=$(echo \"$X\" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')", nil},
		{"GL011 curl into python -c is data", "GL011", "curl -s https://api.example.com/x | python3 -c 'import json,sys; print(json.load(sys.stdin))'", nil},
		{"GL011 curl into sh on line 2", "GL011", "echo start\ncurl -sSL https://get.example.com | sh", []int{6}},
		{"GL015 ref only in the source of docker tag", "GL015", `docker tag "$IMG:$CI_COMMIT_REF_SLUG" "$IMG:latest"`, nil},
		{"GL015 ref only in a label", "GL015", `docker build --label "ref=$IMG:$CI_COMMIT_REF_NAME" -t "$IMG:$CI_COMMIT_SHA" .`, nil},
		{"GL015 ref as the target of docker tag", "GL015", "echo x\ndocker tag \"$IMG:$CI_COMMIT_SHA\" \"$IMG:$CI_COMMIT_REF_SLUG\"", []int{6}},
		{"GL015 build -t", "GL015", `docker build -t $IMG:${CI_COMMIT_REF_NAME} .`, []int{5}},
		{"GL016 http URL in another command", "GL016", "BASEURL=\"http://downloads.example.org/files\"\ncurl -X POST \"$WEBHOOK\" --data-binary @payload.json", nil},
		{"GL016 http download on line 2", "GL016", "echo x\ncurl -o f http://downloads.example.org/f", []int{6}},
		{"GL021 redirect on the continued line", "GL021", "echo \"{\\\"auth\\\":\\\"$CI_REGISTRY_PASSWORD\\\"}\" \\\n  > /kaniko/.docker/config.json", nil},
		{"GL025 tag goes to jq, not curl", "GL025", `RELEASE_ID=$(curl -s "https://api.example.com/releases" | jq -r --arg ver "${CI_COMMIT_TAG}" '.[] | select(.name == $ver) | .id')`, nil},
		{"GL025 tag in the curl URL", "GL025", `curl -s "https://api.example.com/releases/${CI_COMMIT_REF_NAME}"`, []int{5}},
		{"GL032 echo and key variable in different commands", "GL032", "echo \"Rolling back\"\nterraform init -backend-config=\"key=${TF_STATE_KEY}\"", nil},
		{"GL032 public key into .pub", "GL032", "echo $STAGING_SSH_PUBLIC_KEY | base64 -d > ~/.ssh/id_rsa.pub", nil},
		{"GL032 public key var into .pub", "GL032", `echo "$SSH_RUNNER_KEY_PUB" >> ~/.ssh/id_ed25519.pub`, nil},
		{"GL032 private key into id_rsa", "GL032", "mkdir -p ~/.ssh\necho \"$DEPLOY_KEY\" | base64 -d > ~/.ssh/id_rsa", []int{6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y := "job:\n  image: alpine:3.20.3\n  script:\n    - |\n      " + strings.ReplaceAll(tc.block, "\n", "\n      ") + "\n"
			doc, err := parser.Parse([]byte(y), "t.yml")
			if err != nil {
				t.Fatal(err)
			}
			var got []int
			for _, f := range rules[tc.rule].Check(doc.Root, "t.yml") {
				got = append(got, f.Line)
			}
			if len(got) != len(tc.lines) {
				t.Fatalf("expected findings on lines %v, got %v", tc.lines, got)
			}
			for i := range got {
				if got[i] != tc.lines[i] {
					t.Fatalf("expected findings on lines %v, got %v", tc.lines, got)
				}
			}
		})
	}
}

func TestGL032_EchoInSubstitution(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{`ssh-add <(echo "$SSH_PRIVATE_KEY")`, 1},
		{`ssh-add <(echo $SSH_PRIVATE_KEY | base64 --decode)`, 1},
		{`export AUTH="Basic $(echo -n "${API_USER}:${API_KEY}" | base64)"`, 1},
		{`ssh-add <(echo "$SSH_PUBLIC_KEY")`, 0},
		{`ssh-add <(echo '$SSH_PRIVATE_KEY')`, 0},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - "+strconv.Quote(tc.script)+"\n"), "t.yml")
		if err != nil {
			t.Fatal(err)
		}
		if f := GL032.Check(doc.Root, "t.yml"); len(f) != tc.want {
			t.Errorf("%s: expected %d, got %d", tc.script, tc.want, len(f))
		}
	}
}
