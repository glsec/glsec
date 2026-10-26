// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl024 struct{}

var GL024 = &gl024{}

func (r *gl024) ID() string { return "GL024" }

var (
	// pipefailRe matches a line that enables pipefail.
	pipefailRe = regexp.MustCompile(`\bpipefail\b`)
)

func (r *gl024) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	inherit := NewInheritance(doc)
	pipefail := nodeMemo[bool]{}
	firstPipe := nodeMemo[int]{} // index of the item line, or -1
	hasPipefail := func(l *yaml.Node) bool {
		return pipefail.get(l, func() bool { return pipefailRe.MatchString(l.Value) })
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)
		if len(lines) == 0 {
			return
		}
		// Windows runners run PowerShell, which has no pipefail (#615).
		if inherit.RunsOnWindows(job) {
			return
		}

		// Check if pipefail is set anywhere in the job's script, including the
		// before_script/script it inherits through extends: or default: (#615).
		// An inherited after_script runs in a separate shell, so it doesn't count.
		for _, l := range lines {
			if hasPipefail(l) {
				return
			}
		}
		for _, key := range []string{"before_script", "script"} {
			if parser.FindKey(job, key) != nil {
				continue
			}
			if seq := inherit.Key(job, key); isScriptList(seq) {
				for _, l := range seq.Content {
					if l.Kind == yaml.ScalarNode && hasPipefail(l) {
						return
					}
				}
			}
		}

		// Find the first command whose output is piped. A | inside quotes, as
		// in sed "s|a|b|" or grep "a|b", is part of an argument.
		for _, l := range lines {
			at := firstPipe.get(l, func() int {
				for _, cmd := range shellCommands(l.Value) {
					if cmd.piped {
						return cmd.line
					}
				}
				return -1
			})
			if at < 0 {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL024",
				Severity: finding.Warn,
				Job:      name.Value,
				Message:  "script uses a pipe without set -o pipefail — failures in all but the last command are silently ignored",
				File:     file,
				Line:     parser.ScalarContentLine(l, at),
			}
			if at == 0 {
				f.Col = l.Column
			}
			findings = append(findings, f)
			return // one finding per job
		}
	})

	return findings
}
