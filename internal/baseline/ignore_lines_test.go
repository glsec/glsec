// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// A .glsec-ignore used as --baseline must be read like suppress.LoadIgnoreFile
// reads it: whitespace-separated, rule ID in the second field, optional
// exp: and other trailing fields ignored, malformed lines skipped.
func TestLoadIgnore_LineForms(t *testing.T) {
	content := `# comment
ci.yml:3 GL001
ci.yml:4	GL002
  ci.yml:5   GL003   exp:2999-01-01
ci.yml:10 GL004 trailing words
ci.yml:7
GL005
ci.yml GL006
ci.yml:0 GL007
ci.yml:abc GL008
ci.yml:-2 GL009
ci.yml: GL010
`
	path := filepath.Join(t.TempDir(), ".glsec-ignore")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		rule string
		new  bool
	}{
		{"GL001", false},
		{"GL002", false}, // tab-separated
		{"GL003", false}, // with exp:
		{"GL004", false}, // trailing fields
		{"GL005", true},  // line had no file:line
		{"GL006", true},  // location without a colon
		{"GL007", true},  // line number 0, not a valid position
		{"GL008", true},  // non-numeric line number
		{"GL009", true},  // negative line number
		{"GL010", true},  // empty line number
		{"GL099", true},  // never listed
	}
	for _, tt := range tests {
		f := finding.Finding{RuleID: tt.rule, File: "ci.yml", Line: 1, Message: "m"}
		if got := b.IsNew(f); got != tt.new {
			t.Errorf("IsNew(%s) = %v, want %v", tt.rule, got, tt.new)
		}
	}
}

// A read that fails part way through, here a line past bufio.Scanner's limit,
// is an error instead of a silently truncated baseline, as in
// suppress.LoadIgnoreFile (#1460).
func TestLoadIgnore_ReadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".glsec-ignore")
	content := "ci.yml:3 GL001\n" + strings.Repeat("x", 64*1024+1) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a read failure past the scanner limit should be an error, not silently dropped lines")
	}
}
