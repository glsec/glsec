// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	glsecdocs "github.com/glsec/glsec/docs"
	"github.com/glsec/glsec/rules"
)

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

// The severity column of docs/rules.md is written by hand; it has to agree
// with the rule docs that glsec list reads (#696).
func TestRulesOverviewSeverity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "rules.md"))
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile(`(?m)^\| \[(GL\d{3})\]\([^)]*\) \| ([^|]*)\|`)
	seen := 0
	for _, m := range row.FindAllStringSubmatch(string(data), -1) {
		raw, err := glsecdocs.FS.ReadFile("rules/" + m[1] + ".md")
		if err != nil {
			t.Errorf("%s: %v", m[1], err)
			continue
		}
		want := normalizeSeverity(parseExplainDoc(raw).severity)
		if got := normalizeSeverity(m[2]); got != want {
			t.Errorf("docs/rules.md lists %s as %q, docs/rules/%s.md says %q", m[1], got, m[1], want)
		}
		seen++
	}
	if seen != len(rules.All()) {
		t.Errorf("docs/rules.md has %d rule rows, want %d", seen, len(rules.All()))
	}
}
