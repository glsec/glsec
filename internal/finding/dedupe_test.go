// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package finding

import "testing"

func TestDedupe(t *testing.T) {
	in := []Finding{
		{RuleID: "GL001", Severity: Warn, Job: "build", Message: `job "build" uses node:latest`, File: "f", Line: 3, Col: 10},
		{RuleID: "GL001", Severity: Error, Job: "deploy", Message: `job "deploy" uses node:latest`, File: "f", Line: 3, Col: 10},
		{RuleID: "GL001", Severity: Warn, Job: "build", Message: `job "build" uses node:latest`, File: "f", Line: 9, Col: 10},
		{RuleID: "GL051", Severity: Warn, Job: "build", Message: `input "a"`, File: "f", Line: 3, Col: 10},
		{RuleID: "GL051", Severity: Warn, Job: "build", Message: `input "b"`, File: "f", Line: 3, Col: 10},
		{RuleID: "GL001", Severity: Warn, Job: "a", Message: `image "alpine:latest"`, File: "f", Line: 5, Col: 1},
		{RuleID: "GL001", Severity: Warn, Job: "b", Message: `image "alpine:latest"`, File: "f", Line: 5, Col: 1},
	}
	out := Dedupe(in)
	if len(out) != 5 {
		t.Fatalf("got %d findings, want 5: %+v", len(out), out)
	}
	if out[0].Job != "build" || out[0].Severity != Error {
		t.Errorf("merged finding = %+v, want first job and highest severity", out[0])
	}
}
