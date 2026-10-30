// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

// findings078 runs GL078 on content as the document's source, since the rule
// scans the raw bytes rather than the parsed YAML tree. The control characters
// under test are written as \u escapes so this source file itself stays clean
// (and does not trip GL078-style scanners).
func findings078(t *testing.T, content string) []finding.Finding {
	t.Helper()
	return GL078.CheckDocument(&parser.Document{Source: []byte(content)}, "gitlab-ci.yml")
}

func TestGL078_ZeroWidthSpace(t *testing.T) {
	f := findings078(t, "build:\n  script:\n    - echo \"hi\u200bthere\"\n")
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for zero-width space, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if f[0].Line != 3 {
		t.Errorf("expected finding on line 3, got %d", f[0].Line)
	}
}

func TestGL078_RLOOverride(t *testing.T) {
	f := findings078(t, "build:\n  script:\n    - echo \"admin\u202eresu\"\n")
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for RLO override, got %d", len(f))
	}
}

func TestGL078_MultipleChars(t *testing.T) {
	f := findings078(t, "build:\n  script:\n    - echo \"a\u200bb\"\n    - echo \"c\u2066d\u2069e\"\n")
	if len(f) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(f))
	}
}

func TestGL078_SoftHyphenAndWordJoiner(t *testing.T) {
	f := findings078(t, "build:\n  script:\n    - echo \"x\u00ady\u2060z\"\n")
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL078_LeadingBOMAllowed(t *testing.T) {
	f := findings078(t, "\ufeffbuild:\n  script:\n    - echo ok\n")
	if len(f) != 0 {
		t.Fatalf("expected no finding for a single leading BOM, got %d", len(f))
	}
}

func TestGL078_NonLeadingBOMFlagged(t *testing.T) {
	f := findings078(t, "build:\n  script:\n    - echo \"a\ufeffb\"\n")
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a non-leading BOM, got %d", len(f))
	}
}

func TestGL078_CleanFile(t *testing.T) {
	f := findings078(t, "build:\n  script:\n    - echo \"perfectly normal\"\n    - make test\n")
	if len(f) != 0 {
		t.Errorf("expected no findings for a clean file, got %d", len(f))
	}
}

func TestGL078_JoinerInTextContexts(t *testing.T) {
	// Joiners are spelling, not payload, in these contexts.
	tests := []struct{ name, content string }{
		{"Persian ZWNJ", "build:\n  script:\n    - echo \"| Android | [app.apk - اندروید (توصیه\u200cشده)](app.apk) |\"\n"},
		{"Devanagari ZWNJ", "build:\n  script:\n    - echo \"क\u200cष\"\n"},
		{"Devanagari ZWJ", "build:\n  script:\n    - echo \"क\u200dष\"\n"},
		{"emoji ZWJ", "build:\n  script:\n    - echo \"👨\u200d👩\"\n"},
		{"emoji ZWJ with variation selector", "build:\n  script:\n    - echo \"❤\ufe0f\u200d🔥\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if f := findings078(t, tt.content); len(f) != 0 {
				t.Fatalf("expected no finding, got %d", len(f))
			}
		})
	}
}

func TestGL078_JoinerOutsideText(t *testing.T) {
	tests := []struct{ name, content string }{
		{"ZWNJ between ASCII", "build:\n  script:\n    - echo \"a\u200cb\"\n"},
		{"ZWNJ next to punctuation", "build:\n  script:\n    - echo \"a\u200c\"\n"},
		{"ZWNJ between Latin and Arabic", "build:\n  script:\n    - echo \"a\u200cش\"\n"},
		{"ZWJ between ASCII", "build:\n  script:\n    - echo \"a\u200db\"\n"},
		{"leading ZWNJ", "build:\n  script:\n    - echo \"\u200cabc\"\n"},
		{"trailing ZWJ", "build:\n  script:\n    - echo \"abc\u200d\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if f := findings078(t, tt.content); len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
		})
	}
}

func TestGL078_BidiStillFlaggedInRTLText(t *testing.T) {
	f := findings078(t, "build:\n  script:\n    - echo \"שלום\u202eאב\"\n")
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a bidirectional control, got %d", len(f))
	}
}

func TestGL078_Column(t *testing.T) {
	f := findings078(t, "build:\n  script:\n    - echo \"\u200bx\"\n")
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	// Line 3 is 4 spaces + `- echo "` (8 chars) so the quote is at column 12 and
	// the zero-width space immediately after it sits at column 13.
	if f[0].Col != 13 {
		t.Errorf("expected column 13, got %d", f[0].Col)
	}
}

// The rule reads the bytes glsec parsed, not the file again: with stdin input
// and --stdin-filename the file on disk holds something else (#833).
func TestGL078_ReadsDocumentSourceNotDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".gitlab-ci.yml")
	if err := os.WriteFile(path, []byte("build:\n  script: [make]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := &parser.Document{Source: []byte("build:\n  script: [\"ma\u202eke\"]\n")}
	if f := GL078.CheckDocument(doc, path); len(f) != 1 {
		t.Errorf("expected 1 finding from the document source, got %d", len(f))
	}
	if f := GL078.Check(nil, path); f != nil {
		t.Errorf("Check reads nothing itself, got %d findings", len(f))
	}
}

func TestGL078_LineBreakCharacters(t *testing.T) {
	tests := []struct {
		name, content string
		code          rune
	}{
		{"lone CR", "build:\n  script:\n    - echo hi\r    - echo hidden\n", '\r'},
		{"NEL", "build:\n  script:\n    - echo hi\u0085\n", 0x0085},
		{"line separator", "build:\n  script:\n    - echo hi\u2028\n", 0x2028},
		{"paragraph separator", "build:\n  script:\n    - echo hi\u2029\n", 0x2029},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := findings078(t, tt.content)
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Line != 3 || f[0].Col != 14 {
				t.Errorf("finding at %d:%d, want 3:14", f[0].Line, f[0].Col)
			}
			if want := fmt.Sprintf("U+%04X", tt.code); !strings.Contains(f[0].Message, want) {
				t.Errorf("message %q does not name %s", f[0].Message, want)
			}
		})
	}
}

func TestGL078_CRLFAllowed(t *testing.T) {
	if f := findings078(t, "build:\r\n  script:\r\n    - echo hi\r\n"); len(f) != 0 {
		t.Errorf("CRLF line endings: expected no finding, got %d", len(f))
	}
}

// A lone CR that ends the file shifts nothing (#1001).
func TestGL078_CRAtEndOfFile(t *testing.T) {
	for content, want := range map[string]int{
		"pages:\n  script:\n    - echo hi\n  only:\n    - main\r":    0,
		"pages:\n  script:\n    - echo hi\n  only:\n    - main\r \n": 0,
		"pages:\n  script:\n    - echo hi\r    - echo hidden\n":      1,
		"pages:\r\n  script:\r\n    - echo hi\r\n":                   0,
	} {
		if got := len(findings078(t, content)); got != want {
			t.Errorf("%q: got %d findings, want %d", content, got, want)
		}
	}
}
