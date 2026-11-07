// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestRun_AuditBypassesUnreadableIgnoreFile(t *testing.T) {
	for _, kind := range []string{"directory", "permission denied"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "permission denied" && (runtime.GOOS == "windows" || os.Getuid() == 0) {
				t.Skip("chmod 000 does not stop a Windows or root reader")
			}
			setupCLI(t, map[string]string{".gitlab-ci.yml": errorPipeline})
			if kind == "directory" {
				if err := os.Mkdir(".glsec-ignore", 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(".glsec-ignore", []byte(".gitlab-ci.yml:2 GL001\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(".glsec-ignore", 0); err != nil {
					t.Fatal(err)
				}
			}
			for _, audit := range []bool{false, true} {
				var out, stderr bytes.Buffer
				args := []string{"--no-cache", "--only", "GL001", "--format", "json"}
				if audit {
					args = append(args, "--no-ignores")
				}
				code := run(args, &out, &stderr)
				var report struct {
					Findings []struct{ Rule string }
					Errors   []struct{ Message string }
				}
				if err := json.Unmarshal(out.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				if audit {
					if code != 1 || len(report.Findings) != 1 || report.Findings[0].Rule != "GL001" || len(report.Errors) != 0 {
						t.Fatalf("audit exit %d, stdout %s, stderr %s", code, &out, &stderr)
					}
				} else if code != 2 || len(report.Errors) != 1 || !strings.Contains(report.Errors[0].Message, ".glsec-ignore") {
					t.Fatalf("normal scan exit %d, stdout %s, stderr %s", code, &out, &stderr)
				}
			}
		})
	}
}
