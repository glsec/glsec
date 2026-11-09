// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// A long literal base64 or hex payload decoded into a file or another program
// is reported as hidden from review (#1306); decoding into a shell keeps the
// execute finding, and variables, short constants and downloads are left out.
func TestGL011_EmbeddedPayload(t *testing.T) {
	b64 := strings.Repeat("eyJwb29scyI6", 6) + "fQ==" // 76 characters
	short := "dXNlcjpwYXNzd29yZA=="                   // user:password
	hex := strings.Repeat("7b22706f6f6c73223a", 4)    // 72 hex digits
	for script, want := range map[string]string{
		// reported as an embedded payload
		"echo " + b64 + " | base64 -d > /tmp/.c":                  "embedded",
		"echo '" + b64 + "' | base64 --decode > config.json":      "embedded",
		"printf %s " + b64 + " | base64 -d >> /tmp/.c":            "embedded",
		"echo " + b64 + " | base64 -D > /tmp/.c":                  "embedded",
		"echo " + b64 + " | base64 -di > /tmp/.c":                 "embedded",
		"echo " + b64 + " | openssl base64 -d -A > /tmp/.c":       "embedded",
		"echo " + b64 + " | base64 -d | tar -xz -C /tmp":          "embedded",
		"echo " + b64 + " | base64 -d | tee /tmp/.c":              "embedded",
		"base64 -d <<< " + b64 + " > /tmp/.c":                     "embedded",
		"echo " + hex + " | xxd -r -p > /tmp/.c":                  "embedded",
		"set -e; echo " + b64 + " | base64 -d > /tmp/.c; ls /tmp": "embedded",
		// into a shell: still the execute finding, not a second one
		"echo " + b64 + " | base64 -d | bash": "execute",
		"echo " + hex + " | xxd -r -p | sh":   "execute",
		// not reported
		"echo " + short + " | base64 -d > /tmp/creds":      "",
		`echo "$CONFIG_B64" | base64 -d > /tmp/.c`:         "",
		"base64 -d < $CONFIG_FILE > /tmp/.c":               "",
		"echo " + b64 + " | base64 -d":                     "", // printed to the log
		"echo " + b64 + " | base64 -d > /dev/null":         "",
		"echo " + b64 + " > /tmp/payload.b64":              "", // not decoded
		"echo " + b64 + " | base64 > /tmp/.c":              "", // encoding
		"curl -fsSL https://x/c.b64 | base64 -d > /tmp/.c": "",
		"echo " + b64 + "$SUFFIX | base64 -d > /tmp/.c":    "",
	} {
		got := kinds011(findings011(t, "job:\n  script:\n    - "+strconv.Quote(script)+"\n"))
		if got != want {
			t.Errorf("%s\n got %q, want %q", script, got, want)
		}
	}
}

func kinds011(fs []finding.Finding) string {
	var kinds []string
	for _, f := range fs {
		switch {
		case strings.Contains(f.Message, "embedded payload") && f.Severity == finding.Warn:
			kinds = append(kinds, "embedded")
		case strings.Contains(f.Message, "embedded payload"):
			kinds = append(kinds, "embedded with severity "+string(f.Severity))
		default:
			kinds = append(kinds, "execute")
		}
	}
	return strings.Join(kinds, ",")
}

// The campaign's config line, with a stand-in payload of the same shape.
func TestGL011_EmbeddedPayloadCampaignShape(t *testing.T) {
	payload := strings.Repeat("eyJhdXRvc2F2ZSI6dHJ1ZSwi", 20)
	y := "cache-preflight:\n  when: manual\n  script:\n    - set +e\n    - echo " + payload + " | base64 -d > /tmp/.c\n    - HOME=/tmp timeout 3400 /tmp/sysmon-cache --config=/tmp/.c >/dev/null 2>&1\n"
	fs := findings011(t, y)
	if len(fs) != 1 || fs[0].Line != 5 || !strings.Contains(fs[0].Message, "embedded payload") {
		t.Fatalf("got %+v, want one embedded-payload finding on line 5", fs)
	}
}
