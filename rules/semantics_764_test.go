// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

func TestRuleSemantics764(t *testing.T) {
	rules := map[string]interface {
		Check(doc *yaml.Node, file string) []finding.Finding
	}{"GL010": GL010, "GL026": GL026, "GL045": GL045, "GL047": GL047, "GL062": GL062, "GL071": GL071}
	for _, tc := range []struct {
		name, rule, yaml string
		want             int
	}{
		{"GL010 child pipeline", "GL010", "c:\n  trigger:\n    include: c.yml\n    forward:\n      pipeline_variables: true\n", 0},
		{"GL010 other project", "GL010", "c:\n  trigger:\n    project: g/p\n    forward:\n      pipeline_variables: true\n", 1},
		{"GL045 npm provenance", "GL045", "release:\n  stage: release\n  id_tokens:\n    SIGSTORE_ID_TOKEN:\n      aud: sigstore\n  script:\n    - npm publish --provenance --access public\n", 0},
		{"GL045 twine attestations", "GL045", "release:\n  stage: release\n  script:\n    - twine upload --attestations dist/*\n", 0},
		{"GL045 plain npm publish", "GL045", "release:\n  stage: release\n  script:\n    - npm publish\n", 1},
		{"GL026 submodule --checkout", "GL026", "j:\n  script:\n    - git submodule update --init --checkout\n", 0},
		{"GL026 config checkout.defaultRemote", "GL026", "j:\n  script:\n    - git config checkout.defaultRemote origin\n", 0},
		{"GL026 lfs checkout", "GL026", "j:\n  script:\n    - git lfs checkout\n", 0},
		{"GL026 -B", "GL026", "j:\n  script:\n    - git checkout -B weblate FETCH_HEAD\n", 0},
		{"GL026 file restore", "GL026", "j:\n  script:\n    - git checkout -- doc/conf.py\n    - git checkout .\n    - git checkout $CI_COMMIT_TAG -- docs/\n", 0},
		{"GL026 SHA variable", "GL026", "j:\n  script:\n    - git checkout -f $CI_COMMIT_SHA\n    - git checkout ${CI_MERGE_REQUEST_DIFF_BASE_SHA}\n", 0},
		{"GL026 branch after third-party clone", "GL026", "j:\n  script:\n    - git clone --branch v1 https://github.com/org/deps.git deps\n    - git -C deps checkout main\n", 2},
		{"GL026 branch without clone", "GL026", "j:\n  script:\n    - git -C deps checkout main\n", 0},
		{"GL047 loopback VM", "GL047", "j:\n  script:\n    - ssh -p 10022 root@127.0.0.1 \"uname -a\"\n", 0},
		{"GL047 remote root", "GL047", "j:\n  script:\n    - ssh root@prod.example.com uptime\n", 1},
		{"GL062 captured", "GL062", "j:\n  script:\n    - JAVA_HOMES=$(env | grep -E '^JAVA_' | paste -sd,)\n    - for t in $(env | grep TAGS | cut -f2 -d=); do echo $t; done\n", 0},
		{"GL062 dump", "GL062", "j:\n  script:\n    - env | sort\n", 1},
		{"GL071 disjoint refs", "GL071", "stages: [test, deploy]\nload-test:\n  stage: test\n  when: manual\n  only: [develop]\n  script: [x]\ndeploy:\n  stage: deploy\n  environment: production\n  only: [main]\n  script: [x]\n", 0},
		{"GL071 same ref", "GL071", "stages: [test, deploy]\napprove:\n  stage: test\n  when: manual\n  only: [main]\n  script: [x]\ndeploy:\n  stage: deploy\n  environment: production\n  only: [main]\n  script: [x]\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.yaml), "t.yml")
			if err != nil {
				t.Fatal(err)
			}
			if f := rules[tc.rule].Check(doc.Root, "t.yml"); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(f), f)
			}
		})
	}
}
