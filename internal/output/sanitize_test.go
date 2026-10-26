// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func TestSanitize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"build", "build"},
		{"déploy ✓", "déploy ✓"},
		{"a\x1b[2Kb", `a\x1b[2Kb`},
		{"a\rb\nc\td", `a\x0db\x0ac\x09d`},
		{"\x00\x7f", `\x00\x7f`},
		{"a\u0085b\u2028c\u2029", "a\\u0085b\\u2028c\\u2029"},
		{"a\u202eb\u2066c", "a\\u202eb\\u2066c"},
		{"a\u200eb\u200fc\u061cd", "a\\u200eb\\u200fc\\u061cd"},
	}
	for _, tt := range tests {
		if got := Sanitize(tt.in); got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if got := sanitizeSource("\tscript:\x1b"); got != "\tscript:\\x1b" {
		t.Errorf("sanitizeSource kept or dropped the wrong characters: %q", got)
	}
}

func TestWrite_EscapesFileContent(t *testing.T) {
	f := finding.Finding{
		RuleID:   "GL001",
		Severity: finding.Error,
		File:     "ci\r.yml",
		Line:     3,
		Job:      "b\x1b[0Ksection_start:1:x[collapsed=true]\r\x1b[0Kglsec: all checks passed\nerror[GL000]: fake",
		Message:  "msg\x1b[8m",
	}
	for _, format := range []Format{FormatText, FormatTable} {
		var buf bytes.Buffer
		if err := Write(&buf, format, []finding.Finding{f}, 1, false, false); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if strings.ContainsAny(out, "\x1b\r") {
			t.Errorf("%s output contains a raw escape or carriage return: %q", format, out)
		}
		if strings.Contains(out, "\nerror[GL000]") {
			t.Errorf("%s output contains a forged line: %q", format, out)
		}
	}
}
