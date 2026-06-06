package main

import (
	"os"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func TestFilterNewOnly_JSONSnapshotBaseline(t *testing.T) {
	dir := t.TempDir()
	snap := dir + "/baseline.json"
	if err := os.WriteFile(snap, []byte(`{"findings":[{"rule":"GL001","file":"a.yml","line":2,"message":"old"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := []finding.Finding{
		{RuleID: "GL001", File: "a.yml", Line: 7, Message: "old"}, // drifted, in baseline
		{RuleID: "GL001", File: "a.yml", Line: 9, Message: "new"}, // not in baseline
	}
	got := filterNewOnly(findings, snap)
	if len(got) != 1 || got[0].Message != "new" {
		t.Fatalf("expected only the new finding, got %+v", got)
	}
}

func TestFilterNewOnly_MissingDefaultBaselineIsEmpty(t *testing.T) {
	t.Chdir(t.TempDir()) // no .glsec-ignore here
	findings := []finding.Finding{{RuleID: "GL001", File: "a.yml", Line: 2, Message: "x"}}
	if got := filterNewOnly(findings, ""); len(got) != 1 {
		t.Fatalf("missing default baseline should treat everything as new, got %d", len(got))
	}
}
