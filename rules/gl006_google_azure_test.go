// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// Built at run time from split literals, so no contiguous key is in the
// source (GitHub push protection); neither is a real key.
var (
	googleAPIKey = "AI" + "za" + "SyD3mR9xQ2vL7kP0wN4tB8cF1hJ6gZ5eUaY"
	azureSecret  = "abc" + "8Q~" + "x1Y2z3W4v5U6t7S8r9Q0p.O_n~M-l3K4j"
)

func TestGL006_GoogleAndAzure(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"Google API key", googleAPIKey},
		{"Azure AD client secret", azureSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings006(t, "variables:\n  VALUE: \""+tc.value+"\"\nbuild:\n  script: [echo ok]\n")
			if len(f) != 1 || !strings.Contains(f[0].Message, tc.name) {
				t.Errorf("got %v, want one %s finding", f, tc.name)
			}
			if f := findings088(t, "build:\n  script:\n    - ./deploy.sh --key "+tc.value+" --env prod\n"); len(f) != 1 || !strings.Contains(f[0].Message, tc.name) {
				t.Errorf("script line: got %v, want one %s finding", f, tc.name)
			}
		})
	}
}

func TestGL006_GoogleAndAzureStayQuiet(t *testing.T) {
	for _, v := range []string{
		googleAPIKey[:len(googleAPIKey)-1],                  // one character short
		googleAPIKey + "a",                                  // one character long
		"AI" + "za" + "SyEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMP", // placeholder
		"AI" + "za" + strings.Repeat("x", 34) + "!",
		azureSecret[:len(azureSecret)-4],   // too short
		"abcxQ~" + strings.Repeat("a", 32), // no digit before Q~
		"abc8Q~" + "example" + strings.Repeat("a", 26),
		"AIzaSy",
	} {
		if f := findings006(t, "variables:\n  VALUE: \""+v+"\"\nbuild:\n  script: [echo ok]\n"); len(f) != 0 {
			t.Errorf("%q: got %v, want no finding", v, f)
		}
	}
}
