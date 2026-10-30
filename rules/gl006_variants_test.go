// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// knownFormatVariants are the variants of #926 next to a format each pattern
// matched before, which has to keep matching. Values are built from split
// literals (GitHub push protection); none is a real token.
func knownFormatVariants() []struct{ name, value string } {
	alnum := func(n int) string { return tokenBody("aB3xQ9zK7m", n) }
	upper := func(n int) string { return tokenBody("AB3XQ9ZK7M", n) }
	return []struct{ name, value string }{
		{"AWS access key", "AK" + "IA" + upper(16)},
		{"AWS access key", "A3" + "TX" + upper(16)},
		{"AWS access key", "AB" + "IA" + upper(16)},
		{"AWS access key", "AC" + "CA" + upper(16)},
		{"Stripe secret key", "sk" + "_live_" + alnum(24)},
		{"Stripe secret key", "rk" + "_live_" + alnum(24)},
		{"Stripe secret key", "rk" + "_test_" + alnum(24)},
		{"Stripe secret key", "sk" + "_prod_" + alnum(24)},
		{"Slack token", "xo" + "xb-" + alnum(30)},
		{"Slack token", "xoxe." + "xoxp-1-" + alnum(163)},
		{"Slack token", "xoxe." + "xoxb-1-" + alnum(166)},
		{"Slack token", "xo" + "xe-1-" + alnum(146)},
		{"Slack app-level token", "xa" + "pp-1-A0" + upper(8) + "-1234567890123-" + tokenBody("0123456789abcdef", 64)},
		{"Slack webhook URL", "https://hooks.slack.com/" + "services/T0" + upper(8) + "/B0" + upper(8) + "/" + alnum(24)},
		{"Slack webhook URL", "https://hooks.slack.com/" + "workflows/T0" + upper(8) + "/A0" + upper(8) + "/123456789012345678/" + alnum(24)},
		{"Slack webhook URL", "https://hooks.slack.com/" + "triggers/T0" + upper(8) + "/1234567890123/" + alnum(32)},
		{"Doppler token", "dp." + "pt." + strings.Repeat("a", 43)},
		{"Doppler token", "dp." + "pt." + alnum(43)},
		{"HuggingFace token", "h" + "f_" + alnum(34)},
		{"HuggingFace organization token", "api_" + "org_" + tokenBody("aBcDeFgHiJ", 34)},
		{"PlanetScale token", "pscale_" + "pw_" + alnum(32)},
		{"PlanetScale OAuth token", "pscale_" + "oauth_" + tokenBody("aB3_x-9.Q=", 40)},
		{"PEM private key", "-----BEGIN " + "RSA PRIVATE KEY-----"},
		{"PEM private key", "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----"},
		{"PEM private key", "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----"},
	}
}

func TestGL006_KnownFormatVariants(t *testing.T) {
	for _, tc := range knownFormatVariants() {
		t.Run(tc.value[:min(len(tc.value), 24)], func(t *testing.T) {
			f := findings006(t, "variables:\n  VALUE: \""+tc.value+"\"\nbuild:\n  script: [echo ok]\n")
			if len(f) != 1 || !strings.Contains(f[0].Message, "hardcoded "+tc.name+" ") {
				t.Errorf("%s: got %v, want one %s finding", tc.value, f, tc.name)
			}
			if tc.name == "PEM private key" {
				return // a header, not a token: GL006 matches it in a variable's value
			}
			if f := findings088(t, "build:\n  script:\n    - ./deploy.sh --token "+tc.value+" --env prod\n"); len(f) != 1 || !strings.Contains(f[0].Message, "hardcoded "+tc.name+" ") {
				t.Errorf("script line %s: got %v, want one %s finding", tc.value, f, tc.name)
			}
		})
	}
}

func TestGL006_KnownFormatVariantsStayQuiet(t *testing.T) {
	alnum := func(n int) string { return tokenBody("aB3xQ9zK7m", n) }
	for _, v := range []string{
		"AB" + "IA" + "abc",                                    // too short
		"rk" + "_dev_" + alnum(24),                             // not a Stripe mode
		"xoxe." + "xoxp-1-" + alnum(100),                       // configuration token too short
		"xa" + "pp-1-a0b-123-abc",                              // lowercase team part
		"https://hooks.slack.com/" + "workflows/T0",            // no token
		"api_" + "org_" + "abc123" + alnum(28),                 // digits in an org token
		"api_" + "org_" + "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPL", // placeholder
		"pscale_" + "oauth_" + "short",
		"-----BEGIN " + "PUBLIC KEY-----",
		"-----BEGIN " + "PGP PUBLIC KEY BLOCK-----",
	} {
		if f := findings006(t, "variables:\n  VALUE: \""+v+"\"\nbuild:\n  script: [echo ok]\n"); len(f) != 0 {
			t.Errorf("%q: got %v, want no finding", v, f)
		}
	}
}
