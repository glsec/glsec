// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"
)

func TestRun_InlineExpiryFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, token string
		expired     bool
	}{
		{"word", " exp:tomorrow", true},
		{"unpadded date", " exp:2026-1-01", true},
		{"empty date", " exp:", true},
		{"invalid calendar date", " exp:2026-13-45", true},
		{"trailing garbage", " exp:2999-01-01junk", true},
		{"future date", " exp:2999-01-01", false},
		{"no expiry", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "job:\n  image: node:latest # glsec:ignore GL001" + tc.token + " -- reviewed\n  script: [echo hi]\n"
			code, out, stderr := runCLI(t, map[string]string{".gitlab-ci.yml": src}, "--no-cache", "--only", "GL001", "--format", "json", "--require-ignore-reason")
			var report struct {
				Findings   []struct{ Rule string }
				Suppressed []struct {
					Rule        string
					Suppression struct{ Reason, Expires string }
				}
			}
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatal(err)
			}
			if tc.expired {
				if code != 1 || len(report.Findings) != 1 || report.Findings[0].Rule != "GL001" || len(report.Suppressed) != 0 {
					t.Fatalf("exit %d, stdout %s, stderr %s; want GL001 reported as expired", code, out, stderr)
				}
			} else if code != 0 || len(report.Findings) != 0 || len(report.Suppressed) != 1 || report.Suppressed[0].Suppression.Reason != "reviewed" {
				t.Fatalf("exit %d, stdout %s, stderr %s; want justified suppression", code, out, stderr)
			} else if tc.token != "" && report.Suppressed[0].Suppression.Expires != "2999-01-01" {
				t.Fatalf("expiry lost: %s", out)
			}
		})
	}
}
