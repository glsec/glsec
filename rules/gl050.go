package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl050 struct{}

var GL050 = &gl050{}

func (r *gl050) ID() string { return "GL050" }

var sudoRe = regexp.MustCompile(`\bsudo\b`)

func (r *gl050) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		if strings.HasPrefix(strings.TrimSpace(line.Value), "#") {
			return
		}
		if sudoRe.MatchString(line.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL050",
				Severity: finding.Warn,
				Job:      job,
				Message:  "sudo in CI script escalates privileges — use a container image with required tools pre-installed instead",
				File:     file,
				Line:     line.Line,
				Col:      line.Column,
			})
		}
	})
	return findings
}
