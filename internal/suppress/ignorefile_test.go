// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package suppress

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

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
	m := LoadIgnoreFile(path, "ci.yml")

	var got []string
	for _, e := range m.Entries() {
		if m.IsSuppressed(e.Line, e.RuleID, now) {
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
	if m.IsSuppressed(3, "GL002", now) {
		t.Error("a suppression must only cover its own line and rule")
	}
}

func TestLoadIgnoreFile_MissingFile(t *testing.T) {
	if m := LoadIgnoreFile(filepath.Join(t.TempDir(), "none"), "ci.yml"); len(m) != 0 {
		t.Errorf("a missing ignore file should give no suppressions, got %v", m)
	}
}
