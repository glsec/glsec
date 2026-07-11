package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// findings078 writes content to a temp file and runs GL078 against it, since the
// rule scans raw file bytes by path rather than the parsed YAML tree. The
// control characters under test are written as \u escapes so this source file
// itself stays clean (and does not trip GL078-style scanners).
func findings078(t *testing.T, content string) []finding.Finding {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gitlab-ci.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return GL078.Check(nil, path)
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

func TestGL078_MissingFile(t *testing.T) {
	if f := GL078.Check(nil, filepath.Join(t.TempDir(), "does-not-exist.yml")); f != nil {
		t.Errorf("expected nil for unreadable file, got %d findings", len(f))
	}
}
