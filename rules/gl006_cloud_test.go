// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

const (
	hexAlphabet    = "0123456789abcdef"
	alnumAlphabet  = "aB3xQ9zK7m"
	urlAlphabet    = "aB3_x-9Qz7"
	base64Alphabet = "aB3+x/9Qz7"
)

func uuidLike() string { return "1b2c3d4e-5f60-4a1b-8c2d-3e4f5a6b7c8d" }

// cloudTokens are the formats of #909 besides Google and Azure. Prefixes are
// split so no contiguous token is in the source (GitHub push protection);
// none is a real token.
func cloudTokens() []struct{ name, value, short string } {
	tok := func(prefix, alphabet string, n int) (string, string) {
		return prefix + tokenBody(alphabet, n), prefix + tokenBody(alphabet, n-1)
	}
	var out []struct{ name, value, short string }
	add := func(name, value, short string) {
		out = append(out, struct{ name, value, short string }{name, value, short})
	}
	for _, tc := range []struct {
		name, prefix, alphabet string
		n                      int
	}{
		{"DigitalOcean token", "do" + "p_v1_", hexAlphabet, 64},
		{"HashiCorp Vault service token", "hv" + "s.", urlAlphabet, 90},
		{"HashiCorp Vault batch token", "hv" + "b.", urlAlphabet, 138},
		{"JFrog API key", "AK" + "Cp", alnumAlphabet, 69},
		{"JFrog reference token", "cmV" + "md", alnumAlphabet, 59},
		{"Heroku API key", "HRKU" + "-AA", urlAlphabet, 58},
		{"Fly.io token", "fo" + "1_", urlAlphabet, 43},
		{"Fly.io macaroon token", "fm" + "2_", base64Alphabet, 100},
		{"Grafana Cloud token", "gl" + "c_", base64Alphabet, 32},
		{"Grafana API key", "eyJr" + "Ijoi", alnumAlphabet, 70},
		{"Sentry user token", "sntr" + "yu_", hexAlphabet, 64},
		{"Sentry organization token", "sntrys_" + "eyJpYXQiO", urlAlphabet, 50},
		{"1Password service account token", "op" + "s_eyJ", base64Alphabet, 250},
		{"OpenShift user token", "sha2" + "56~", urlAlphabet, 43},
		{"AWS Bedrock API key", "AB" + "SK", base64Alphabet, 109},
		{"Perplexity API key", "ppl" + "x-", alnumAlphabet, 48},
		{"Prefect API key", "pn" + "u_", alnumAlphabet, 36},
		{"ReadMe API key", "rdm" + "e_", "a3x9z7k0m2", 70},
		{"Infracost API key", "ic" + "o-", alnumAlphabet, 32},
		{"Scalingo API token", "tk-" + "us-", urlAlphabet, 48},
	} {
		v, s := tok(tc.prefix, tc.alphabet, tc.n)
		add(tc.name, v, s)
	}
	add("Grafana service account token",
		"gl"+"sa_"+tokenBody(alnumAlphabet, 32)+"_"+tokenBody(hexAlphabet, 8),
		"gl"+"sa_"+tokenBody(alnumAlphabet, 32)+"_"+tokenBody(hexAlphabet, 7))
	add("Notion integration token",
		"nt"+"n_"+tokenBody("0123456789", 11)+tokenBody(alnumAlphabet, 35),
		"nt"+"n_"+tokenBody("0123456789", 11)+tokenBody(alnumAlphabet, 34))
	add("Sourcegraph access token",
		"sg"+"p_"+tokenBody(hexAlphabet, 16)+"_"+tokenBody(hexAlphabet, 40),
		"sg"+"p_"+tokenBody(hexAlphabet, 16)+"_"+tokenBody(hexAlphabet, 39))
	teams := "https://contoso.webhook.office.com/webhook" + "b2/" + uuidLike() + "@" + uuidLike() + "/IncomingWebhook/" + tokenBody(hexAlphabet, 32) + "/" + uuidLike()
	add("Microsoft Teams webhook URL", teams, strings.TrimSuffix(teams, "8d"))
	return out
}

func TestGL006_CloudTokens(t *testing.T) {
	for _, tc := range cloudTokens() {
		t.Run(tc.name, func(t *testing.T) {
			f := findings006(t, "variables:\n  VALUE: \""+tc.value+"\"\nbuild:\n  script: [echo ok]\n")
			if len(f) != 1 || !strings.Contains(f[0].Message, tc.name) {
				t.Errorf("%s: got %v, want one %s finding", tc.value, f, tc.name)
			}
			if f := findings088(t, "build:\n  script:\n    - ./deploy.sh --token "+tc.value+" --env prod\n"); len(f) != 1 || !strings.Contains(f[0].Message, tc.name) {
				t.Errorf("script line: got %v, want one %s finding", f, tc.name)
			}
			for _, quiet := range []string{tc.short, tc.value[:len(tc.value)-7] + "EXAMPLE"} {
				if f := findings006(t, "variables:\n  VALUE: \""+quiet+"\"\nbuild:\n  script: [echo ok]\n"); len(f) != 0 {
					t.Errorf("%q: got %v, want no finding", quiet, f)
				}
			}
		})
	}
}

func TestGL006_FlyTokenAsFlyctlPrintsIt(t *testing.T) {
	body := tokenBody(base64Alphabet, 120)
	value := "FlyV1 " + "fm" + "2_" + body + "==,fm" + "2_" + body
	f := findings006(t, "variables:\n  FLY: \""+value+"\"\nbuild:\n  script: [echo ok]\n")
	if len(f) != 1 || !strings.Contains(f[0].Message, "Fly.io macaroon token") {
		t.Errorf("got %v, want one Fly.io macaroon token finding", f)
	}
}
