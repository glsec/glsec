package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl061 struct{}

var GL061 = &gl061{}

func (r *gl061) ID() string { return "GL061" }

// pidHostRe matches --pid host / --pid=host.
var pidHostRe = regexp.MustCompile(`--pid[=\s]+host(?:\s|$)`)

func (r *gl061) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerRunRe.MatchString(v) || !pidHostRe.MatchString(v) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL061",
			Severity: finding.Warn,
			Job:      job,
			Message:  "docker run --pid host shares the host PID namespace — the container can see, signal, and read memory of all host processes (other jobs, the runner agent); omit --pid or scope it with --pid container:<id>",
			File:     file,
			Line:     line.Line,
			Col:      line.Column,
		})
	})
	return findings
}
