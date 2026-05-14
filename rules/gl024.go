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
	// realPipeRe matches a shell pipe (|) that is not || (logical OR), |& (stderr+stdout),
	// or >| (force redirect). Requires the preceding char to be neither | nor >.
	realPipeRe = regexp.MustCompile(`(?:^|[^|>])\|[^|&]`)

	// pipefailRe matches a line that enables pipefail.
	pipefailRe = regexp.MustCompile(`\bpipefail\b`)
)

func (r *gl024) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		lines := collectScriptLines(job)
		if len(lines) == 0 {
			return
		}

		// Check if pipefail is set anywhere in the job's script.
		for _, l := range lines {
			if pipefailRe.MatchString(l.Value) {
				return
			}
		}

		// Find the first line that contains a real pipe.
		for _, l := range lines {
			if realPipeRe.MatchString(l.Value) {
				findings = append(findings, finding.Finding{
					RuleID:   "GL024",
					Severity: finding.Warn,
					Message:  "script uses a pipe without set -o pipefail — failures in all but the last command are silently ignored",
					File:     file,
					Line:     l.Line,
					Col:      l.Column,
				})
				return // one finding per job
			}
		}
	})

	return findings
}
