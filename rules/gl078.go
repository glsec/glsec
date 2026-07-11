package rules

import (
	"fmt"
	"os"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl078 struct{}

var GL078 = &gl078{}

func (r *gl078) ID() string { return "GL078" }

// dangerousRunes are Unicode code points that make rendered text differ from
// what is actually parsed/executed — the "Trojan Source" class (CVE-2021-42574).
// Bidirectional controls reorder a line; zero-width and invisible characters
// hide or smuggle payload. None of these appear legitimately in a CI config.
var dangerousRunes = map[rune]string{
	// Bidirectional control characters (reordering attacks).
	0x202A: "LEFT-TO-RIGHT EMBEDDING",
	0x202B: "RIGHT-TO-LEFT EMBEDDING",
	0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE",
	0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2066: "LEFT-TO-RIGHT ISOLATE",
	0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE",
	0x2069: "POP DIRECTIONAL ISOLATE",
	0x061C: "ARABIC LETTER MARK",
	// Zero-width / invisible characters (hidden-payload / homoglyph smuggling).
	0x200B: "ZERO WIDTH SPACE",
	0x200C: "ZERO WIDTH NON-JOINER",
	0x200D: "ZERO WIDTH JOINER",
	0x2060: "WORD JOINER",
	0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
	0x00AD: "SOFT HYPHEN",
}

// Check scans the raw file bytes (not the parsed YAML tree) because these
// control characters are invisible in the node values a tree walk would see.
func (r *gl078) Check(_ *yaml.Node, file string) []finding.Finding {
	data, err := os.ReadFile(file) //nolint:gosec // G304: scanning the file glsec was asked to lint
	if err != nil {
		return nil
	}

	var findings []finding.Finding
	line, col := 1, 1
	for i, ch := range string(data) {
		switch ch {
		case '\n':
			line++
			col = 1
			continue
		// A single leading BOM is legitimate; ignore it but flag any later U+FEFF.
		case 0xFEFF:
			if i == 0 {
				continue
			}
		}
		if name, ok := dangerousRunes[ch]; ok {
			findings = append(findings, finding.Finding{
				RuleID:   "GL078",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"invisible/bidirectional Unicode character U+%04X (%s) at column %d — the rendered file can differ from what runs (Trojan Source, CVE-2021-42574); remove it",
					ch, name, col,
				),
				File: file,
				Line: line,
				Col:  col,
			})
		}
		col++
	}
	return findings
}
