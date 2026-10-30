// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/internal/parser"
	gitlabver "github.com/glsec/glsec/internal/version"
)

const specHeaderYAML = `spec:
  inputs:
    free:
      default: x
---
job:
  script:
    - echo $[[ inputs.free ]]
`

func ruleIDs(t *testing.T, file string) map[string]bool {
	t.Helper()
	doc, err := parser.Parse([]byte(specHeaderYAML), file)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	found, _, _, _ := collectFindings(doc, file, config.Default(), gitlabver.Version{}, true, true)
	ids := map[string]bool{}
	for _, f := range found {
		ids[f.RuleID] = true
	}
	return ids
}

func TestCollectFindings_ComponentTemplateReadsSpecHeader(t *testing.T) {
	ids := ruleIDs(t, "templates/scan.yml")
	if !ids["GL051"] {
		t.Error("expected GL051 to read inputs from the spec header of a component template")
	}
	if ids["GL053"] {
		t.Error("GL053 must not fire on a component template")
	}
}

func TestCollectFindings_RootPipelineWithInputs(t *testing.T) {
	ids := ruleIDs(t, ".gitlab-ci.yml")
	if !ids["GL051"] {
		t.Error("expected GL051 on pipeline-level spec:inputs")
	}
	if !ids["GL053"] {
		t.Error("expected GL053 on a root pipeline that declares spec:inputs")
	}
}
