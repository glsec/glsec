// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
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

// lineBreakRunes are characters the YAML parser treats as line breaks but most
// editors, diffs and GitLab's file view don't. A file containing them parses
// into different lines than a reviewer sees, and findings after them point at
// shifted line numbers. A carriage return is only reported on its own: CRLF
// line endings are fine.
var lineBreakRunes = map[rune]string{
	'\r':   "CARRIAGE RETURN without a following line feed",
	0x0085: "NEXT LINE",
	0x2028: "LINE SEPARATOR",
	0x2029: "PARAGRAPH SEPARATOR",
}

// joinerScripts are the scripts in which U+200C and U+200D are part of normal
// spelling: Arabic-script languages such as Persian and Urdu use the zero width
// non-joiner inside words, and the Indic scripts use both characters in
// conjuncts. Between two letters of these scripts a joiner is text, not a
// Trojan Source payload.
var joinerScripts = []*unicode.RangeTable{
	unicode.Arabic,
	unicode.Devanagari,
	unicode.Bengali,
	unicode.Gurmukhi,
	unicode.Gujarati,
	unicode.Oriya,
	unicode.Tamil,
	unicode.Telugu,
	unicode.Kannada,
	unicode.Malayalam,
	unicode.Sinhala,
}

// emojiRanges holds the blocks that can take part in an emoji ZWJ sequence.
// The standard library has no emoji table; the ranges are deliberately broad
// because they only widen the exemption when both sides of the joiner are
// emoji-like.
var emojiRanges = [][2]rune{
	{0x2190, 0x21FF},   // arrows
	{0x2300, 0x23FF},   // miscellaneous technical
	{0x25A0, 0x25FF},   // geometric shapes
	{0x2600, 0x27BF},   // miscellaneous symbols and dingbats
	{0x2B00, 0x2BFF},   // miscellaneous symbols and arrows
	{0x1F000, 0x1FAFF}, // pictographs, emoji, flags, skin tones
}

func inAnyScript(r rune, scripts []*unicode.RangeTable) bool {
	for _, script := range scripts {
		if unicode.Is(script, r) {
			return true
		}
	}
	return false
}

func isEmoji(r rune) bool {
	for _, rng := range emojiRanges {
		if r >= rng[0] && r <= rng[1] {
			return true
		}
	}
	return false
}

// emojiBefore reports whether the rune at i can be the left side of an emoji
// ZWJ sequence. A U+FE0F variation selector belongs to the emoji before it.
func emojiBefore(runes []rune, i int) bool {
	if i < 0 {
		return false
	}
	if isEmoji(runes[i]) {
		return true
	}
	return runes[i] == 0xFE0F && i > 0 && isEmoji(runes[i-1])
}

func emojiAfter(runes []rune, i int) bool {
	if i >= len(runes) {
		return false
	}
	if isEmoji(runes[i]) {
		return true
	}
	return runes[i] == 0xFE0F && i+1 < len(runes) && isEmoji(runes[i+1])
}

// joinerFitsText reports whether the joiner at runes[i] belongs to ordinary
// text rather than a hidden-payload trick: both neighbours are letters of a
// script that uses it, or it joins an emoji sequence. Everything else stays a
// finding — between ASCII characters, next to code, or between scripts that do
// not use the joiner.
func joinerFitsText(runes []rune, i int) bool {
	if i == 0 || i+1 >= len(runes) {
		return false
	}
	if runes[i] == 0x200D && emojiBefore(runes, i-1) && emojiAfter(runes, i+1) {
		return true
	}
	prev, next := runes[i-1], runes[i+1]
	if !unicode.IsLetter(prev) || !unicode.IsLetter(next) {
		return false
	}
	return inAnyScript(prev, joinerScripts) && inAnyScript(next, joinerScripts)
}

// Check does nothing: the rule needs the raw text, which only
// CheckDocument gets.
func (r *gl078) Check(*yaml.Node, string) []finding.Finding { return nil }

// CheckDocument scans the raw bytes (not the parsed YAML tree) because these
// control characters are invisible in the node values a tree walk would see.
// They are the bytes glsec parsed, not the file read again: for stdin input
// with --stdin-filename the file on disk holds something else (#833).
func (r *gl078) CheckDocument(doc *parser.Document, file string) []finding.Finding {
	var findings []finding.Finding
	line, col := 1, 1
	runes := []rune(string(doc.Source))
	for i, ch := range runes {
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
		crlf := ch == '\r' && i+1 < len(runes) && runes[i+1] == '\n'
		// A CR with only whitespace after it ends the file: nothing follows
		// that could be parsed apart from how it reads (#1001).
		finalCR := ch == '\r' && !crlf && strings.TrimSpace(string(runes[i+1:])) == ""
		if name, ok := lineBreakRunes[ch]; ok && !crlf && !finalCR {
			findings = append(findings, finding.Finding{
				RuleID:   "GL078",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"Unicode line break U+%04X (%s) at column %d — YAML starts a new line here but editors and diffs mostly don't, so the file is parsed differently from how it reads and later findings point at shifted lines; remove it",
					ch, name, col,
				),
				File: file,
				Line: line,
				Col:  col,
			})
		}
		if name, ok := dangerousRunes[ch]; ok {
			if (ch == 0x200C || ch == 0x200D) && joinerFitsText(runes, i) {
				col++
				continue
			}
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
