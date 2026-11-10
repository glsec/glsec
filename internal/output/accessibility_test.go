// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

// Accessibility guard: the text report must carry each finding's severity as a
// word, never through color alone, color must be additive, and the color-off
// path (NO_COLOR / --no-color / a non-terminal) must emit no ANSI escapes. See
// ACCESSIBILITY.md.
func TestTextReportSeverityIsTextNotColorAlone(t *testing.T) {
	findings := []finding.Finding{
		{RuleID: "GL011", Severity: finding.Error, File: ".gitlab-ci.yml", Line: 3, Message: "pipe to bash"},
		{RuleID: "GL053", Severity: finding.Warn, File: ".gitlab-ci.yml", Line: 1, Message: "no workflow:rules"},
		{RuleID: "GL070", Severity: finding.Info, File: "ci/child.yml", Line: 0, Message: "informational"},
	}
	const esc = "\x1b["

	// Color off: every severity word present, no ANSI escape.
	var off bytes.Buffer
	if err := Write(&off, FormatText, findings, 1, false, false); err != nil {
		t.Fatal(err)
	}
	offLower := strings.ToLower(off.String())
	for _, word := range []string{"error", "warn", "info"} {
		if !strings.Contains(offLower, word) {
			t.Errorf("color-off text report missing severity word %q:\n%s", word, off.String())
		}
	}
	if strings.Contains(off.String(), esc) {
		t.Errorf("color-off text report contains an ANSI escape:\n%q", off.String())
	}

	// Color on: the same words are still present (color is additive, not the
	// sole carrier), and an escape appears.
	var on bytes.Buffer
	if err := Write(&on, FormatText, findings, 1, true, true); err != nil {
		t.Fatal(err)
	}
	onLower := strings.ToLower(on.String())
	for _, word := range []string{"error", "warn", "info"} {
		if !strings.Contains(onLower, word) {
			t.Errorf("color-on text report missing severity word %q", word)
		}
	}
	if !strings.Contains(on.String(), esc) {
		t.Error("color-on text report has no ANSI escape, expected color to be applied")
	}
}
