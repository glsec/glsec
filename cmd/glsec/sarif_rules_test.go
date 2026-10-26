// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/rules"
)

// Every rule gets a title, a description, help and a severity in SARIF, and
// its help has no links that only work inside the repository.
func TestSARIFRuleInfoForEveryRule(t *testing.T) {
	for _, r := range rules.All() {
		info := sarifRuleInfo(r.ID())
		switch {
		case info.Title == "" || info.Risk == "" || info.Details == "" || info.Severity == "":
			t.Errorf("%s: incomplete SARIF rule info %+v", r.ID(), info)
		case strings.HasSuffix(info.Risk, ":"):
			t.Errorf("%s: description ends in a colon: %q", r.ID(), info.Risk)
		case strings.Contains(info.Details, ".md)") || strings.Contains(info.Details, "](../"):
			t.Errorf("%s: help has a repository-relative link", r.ID())
		}
	}
}
