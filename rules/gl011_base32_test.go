// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

// Base32 payloads and decode-to-file-then-execute correlation (#1346).
func TestGL011_Base32AndExecChain(t *testing.T) {
	b := "OBZGS3TUMYQGQZLMNRXSA53POJWGIIDUNBUXGIDJOMQGCIDIMFZG23DFONZSA43ZNZ2GQZLUNFRSA4DBPFWG6YLEEBTG64RAORSXG5DTEBXW43DZ"
	for name, tc := range map[string]struct {
		yaml string
		want map[int]string // line -> severity ("" = no finding on that line)
	}{
		"base32 into shell": {
			"job:\n  script:\n    - printf %s " + b + " | base32 -d | sh\n",
			map[int]string{3: "error"},
		},
		"base32 into file": {
			"job:\n  script:\n    - printf %s " + b + " | base32 -d > .cfg\n",
			map[int]string{3: "warn"},
		},
		"base32 file then exec": {
			"job:\n  script:\n    - printf %s " + b + " | base32 -d > .p.sh\n    - sh .p.sh\n",
			map[int]string{3: "error"},
		},
		"data files vs executed script": {
			"job:\n  script:\n" +
				"    - printf %s " + b + " | base32 -d > .patterns\n" +
				"    - printf %s " + b + " | base32 -d > .sweep\n" +
				"    - '{ timeout 5 sh .sweep \"\" .patterns; }'\n",
			map[int]string{3: "warn", 4: "error"},
		},
		"base64 file then exec": {
			"job:\n  script:\n    - printf %s " + b + "aa | base64 -d > .b.sh\n    - bash .b.sh\n",
			map[int]string{3: "error"},
		},
		"executed file is a different file": {
			"job:\n  script:\n    - printf %s " + b + " | base32 -d > .cfg\n    - sh other.sh\n",
			map[int]string{3: "warn"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := map[int]string{}
			for _, f := range findings011(t, tc.yaml) {
				got[f.Line] = string(f.Severity)
			}
			for line, sev := range tc.want {
				if got[line] != sev {
					t.Errorf("line %d: got %q, want %q (all: %v)", line, got[line], sev, got)
				}
			}
			if len(got) != len(tc.want) {
				t.Errorf("got %d findings, want %d: %v", len(got), len(tc.want), got)
			}
		})
	}
}
