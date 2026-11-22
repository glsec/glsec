// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package suppress

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestParseIgnoreLine(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		ok     bool
		file   string
		line   int
		rule   string
		expiry string
	}{
		{raw: "ci.yml:3 GL001", ok: true, file: "ci.yml", line: 3, rule: "GL001"},
		{raw: "  ci.yml:5 \t GL003  exp:2999-01-01 ", ok: true, file: "ci.yml", line: 5, rule: "GL003", expiry: "2999-01-01"},
		{raw: "ci.yml:10 GL004 trailing words", ok: true, file: "ci.yml", line: 10, rule: "GL004"},
		{raw: `c:\ci.yml:9 GL012`, ok: true, file: `c:\ci.yml`, line: 9, rule: "GL012"},
		{raw: "# comment", ok: false},
		{raw: "", ok: false},
		{raw: "   ", ok: false},
		{raw: "ci.yml:7", ok: false},         // one field
		{raw: "GL005", ok: false},            // one field, no colon
		{raw: "ci.yml GL006", ok: false},     // no colon
		{raw: "ci.yml:0 GL007", ok: false},   // zero
		{raw: "ci.yml:abc GL008", ok: false}, // non-numeric
		{raw: "ci.yml:-2 GL009", ok: false},  // negative
		{raw: "ci.yml: GL010", ok: false},    // empty line number
	} {
		got, ok := ParseIgnoreLine(tc.raw)
		if ok != tc.ok {
			t.Errorf("ParseIgnoreLine(%q) ok = %v, want %v", tc.raw, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.File != tc.file || got.Line != tc.line || got.RuleID != tc.rule || got.Expiry != tc.expiry {
			t.Errorf("ParseIgnoreLine(%q) = %+v, want {File:%q Line:%d RuleID:%q Expiry:%q}", tc.raw, got, tc.file, tc.line, tc.rule, tc.expiry)
		}
	}
}

func TestLoadIgnoreFile_MalformedLines(t *testing.T) {
	content := `# comment
ci.yml:3 GL001
ci.yml:4	GL002
  ci.yml:5   GL003   exp:2999-01-01  
ci.yml:6 GL004 exp:2000-01-01
ci.yml:7
GL005
ci.yml GL006
ci.yml:abc GL007
ci.yml:0 GL008
ci.yml:-2 GL009
other.yml:3 GL010
sub/ci.yml:3 GL011
c:\ci.yml:9 GL012

ci.yml:10 GL013 trailing words are ignored
`
	path := filepath.Join(t.TempDir(), ".glsec-ignore")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	m, err := LoadIgnoreFile(path, "ci.yml")
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, e := range m.Entries() {
		if isSuppressed(m, e.Line, e.RuleID, now) {
			got = append(got, e.RuleID)
		}
	}
	sort.Strings(got)
	want := []string{"GL001", "GL002", "GL003", "GL013"}
	if len(got) != len(want) {
		t.Fatalf("active suppressions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("active suppressions = %v, want %v", got, want)
		}
	}
	if !m.ExpiredAt(6, "GL004", now) {
		t.Error("GL004's past expiry should be reported as expired")
	}
	if isSuppressed(m, 3, "GL002", now) {
		t.Error("a suppression must only cover its own line and rule")
	}
}

func TestLoadIgnoreFile_MissingFile(t *testing.T) {
	m, err := LoadIgnoreFile(filepath.Join(t.TempDir(), "none"), "ci.yml")
	if err != nil {
		t.Fatalf("a missing ignore file is not an error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("a missing ignore file should give no suppressions, got %v", m)
	}
}

// TestLoadIgnoreFile_Unreadable: a file that exists but cannot be opened is an
// error, not silent suppressions, matching how an unreadable .glsec.yml fails.
func TestLoadIgnoreFile_Unreadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("chmod 000 does not stop a Windows or root reader")
	}
	path := filepath.Join(t.TempDir(), ".glsec-ignore")
	if err := os.WriteFile(path, []byte("ci.yml:3 GL001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	m, err := LoadIgnoreFile(path, "ci.yml")
	if err == nil {
		t.Fatal("an unreadable ignore file should be an error, not silent suppressions")
	}
	if len(m) != 0 {
		t.Errorf("an unreadable ignore file should return no suppressions, got %v", m)
	}
}

// TestLoadIgnoreFile_ReadError: a read that fails part way through, here a line
// past bufio.Scanner's limit, is an error instead of silently losing the rest
// of the file.
func TestLoadIgnoreFile_ReadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".glsec-ignore")
	content := "ci.yml:3 GL001\n" + strings.Repeat("x", 64*1024+1) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIgnoreFile(path, "ci.yml"); err == nil {
		t.Fatal("a read failure past the scanner limit should be an error, not silently dropped lines")
	}
}
