// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl086 struct{}

var GL086 = &gl086{}

func (r *gl086) ID() string { return "GL086" }

// maxKeyPreview caps how much of the mapping key the message quotes; the key
// is the start of the command, which can be a whole curl invocation.
const maxKeyPreview = 40

// Check reports script items that YAML reads as a mapping: an unquoted ": "
// inside the line, as in curl -H "Authorization: Bearer ...". GitLab rejects
// the pipeline only when it creates it, and the other rules, which read script
// items as strings, never see the command (#727).
func (r *gl086) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(block *yaml.Node, file, job string) {
		for _, item := range block.Content {
			if item.Kind != yaml.MappingNode || len(item.Content) == 0 {
				continue
			}
			key := []rune(item.Content[0].Value)
			preview := string(key)
			if len(key) > maxKeyPreview {
				preview = string(key[:maxKeyPreview]) + "…"
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL086",
				Severity: finding.Error,
				Job:      job,
				Message:  fmt.Sprintf("script line is a YAML mapping, not a command: the unquoted \": \" after %q splits it into key and value, and GitLab rejects the pipeline — quote the whole line or use a block scalar (- |)", preview),
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	})
	return findings
}
