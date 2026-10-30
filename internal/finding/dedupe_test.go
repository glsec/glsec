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

func TestDedupe_NoJob(t *testing.T) {
	in := []Finding{
		{RuleID: "GL053", Severity: Warn, Message: "no workflow:rules", File: "f", Line: 1, Col: 1},
		{RuleID: "GL053", Severity: Warn, Message: "no workflow:rules", File: "f", Line: 1, Col: 1},
		{RuleID: "GL053", Severity: Warn, Message: "no workflow:rules", File: "g", Line: 1, Col: 1},
	}
	if out := Dedupe(in); len(out) != 2 {
		t.Errorf("got %d findings, want 2 (identical job-less findings merge): %+v", len(out), out)
	}
}

func TestDedupe_InfoNeverRaisesSeverity(t *testing.T) {
	in := []Finding{
		{RuleID: "GL016", Severity: Warn, Job: "a", Message: "m", File: "f", Line: 2},
		{RuleID: "GL016", Severity: Info, Job: "b", Message: "m", File: "f", Line: 2},
	}
	out := Dedupe(in)
	if len(out) != 1 || out[0].Severity != Warn {
		t.Errorf("got %+v, want one finding at warn", out)
	}
	out = Dedupe([]Finding{in[1], in[0]})
	if len(out) != 1 || out[0].Severity != Warn {
		t.Errorf("info first: got %+v, want it raised to warn", out)
	}
}

// A suppressed finding an anchor repeats per job is listed once, with the
// first one's suppression and the highest severity.
func TestDedupeSuppressed(t *testing.T) {
	in := []Suppressed{
		{Finding: Finding{RuleID: "GL001", Severity: Warn, Job: "a", Message: `job "a" uses node:latest`, File: "f", Line: 3}, Source: SourceInline, Reason: "pinned"},
		{Finding: Finding{RuleID: "GL001", Severity: Error, Job: "b", Message: `job "b" uses node:latest`, File: "f", Line: 3}, Source: SourceInline, Reason: "pinned"},
		{Finding: Finding{RuleID: "GL001", Severity: Warn, Job: "c", Message: `job "c" uses node:latest`, File: "f", Line: 9}, Source: SourceIgnoreFile},
	}
	out := DedupeSuppressed(in)
	if len(out) != 2 {
		t.Fatalf("got %d, want 2", len(out))
	}
	if out[0].Job != "a" || out[0].Severity != Error || out[0].Reason != "pinned" || out[1].Source != SourceIgnoreFile {
		t.Errorf("got %+v", out)
	}
}
