// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl087 struct{}

var GL087 = &gl087{}

func (r *gl087) ID() string { return "GL087" }

// Check finds nothing: the parser has already removed the duplicates from the
// tree by the time a rule sees it. CheckDocument reports them.
func (r *gl087) Check(*yaml.Node, string) []finding.Finding { return nil }

func gl087Message(d parser.DuplicateKey) string {
	if d.Anchor != "" {
		return fmt.Sprintf("duplicate key %q — the key at line %d replaces this one here; the anchor &%s in its value is still used through its aliases, so give it a key of its own", d.Key.Value, d.Winner.Line, d.Anchor)
	}
	return fmt.Sprintf("duplicate key %q — GitLab ignores this value and uses the one at line %d", d.Key.Value, d.Winner.Line)
}

// CheckDocument reports every key the parser dropped because the same mapping
// has it again later (#633). GitLab uses the last value, so the earlier one is
// dead configuration that readers and reviewers still take at face value.
func (r *gl087) CheckDocument(doc *parser.Document, file string) []finding.Finding {
	findings := make([]finding.Finding, 0, len(doc.DuplicateKeys))
	for _, d := range doc.DuplicateKeys {
		findings = append(findings, finding.Finding{
			RuleID:   "GL087",
			Severity: finding.Warn,
			Job:      d.Job,
			Message:  gl087Message(d),
			File:     file,
			Line:     d.Key.Line,
			Col:      d.Key.Column,
		})
	}
	return findings
}
