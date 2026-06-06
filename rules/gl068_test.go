package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings068(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL068.Check(doc.Root, "test.yml")
}

func TestGL068_Flags(t *testing.T) {
	flagged := []string{
		"set -x",
		"set -euxo pipefail",
		"set -xe",
		"set -o xtrace",
		`[[ "$TRACE" ]] && set -x`,
	}
	for _, line := range flagged {
		f := findings068(t, "job:\n  script:\n    - '"+line+"'\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %q, got %d", line, len(f))
			continue
		}
		if f[0].RuleID != "GL068" || f[0].Severity != finding.Warn {
			t.Errorf("unexpected finding for %q: %+v", line, f[0])
		}
	}
}

func TestGL068_NotFlagged(t *testing.T) {
	clean := []string{
		"set -euo pipefail",          // no x
		"set +x",                     // disabling
		"set -o errexit",             // long form, not xtrace
		"set -x; ./build.sh; set +x", // net effect off — scoped on one line
		"echo set -x",                // not a set command
		"unset XTRACE",               // not `set`
		"# set -x",                   // comment
	}
	for _, line := range clean {
		if f := findings068(t, "job:\n  script:\n    - '"+line+"'\n"); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d: %+v", line, len(f), f)
		}
	}
}

func TestGL068_BeforeAndAfterScript(t *testing.T) {
	f := findings068(t, `
job:
  before_script:
    - set -x
  after_script:
    - set -o xtrace
  script:
    - echo hi
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (before+after script), got %d", len(f))
	}
}
