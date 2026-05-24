package main

import "testing"

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"`error`":                       "error",
		"`warn`":                        "warn",
		"`info`":                        "info",
		"`error` for X; `warn` for Y":   "error/warn",
		"varies by context (see below)": "varies",
		"":                              "varies",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContainsFold(t *testing.T) {
	cats := []string{"CICD-SEC-4", "CICD-SEC-8"}
	if !containsFold(cats, "cicd-sec-4") {
		t.Error("expected case-insensitive match for cicd-sec-4")
	}
	if containsFold(cats, "CICD-SEC-1") {
		t.Error("did not expect a match for CICD-SEC-1")
	}
	if containsFold(nil, "CICD-SEC-4") {
		t.Error("empty list should not match")
	}
}
