package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl058 struct{}

var GL058 = &gl058{}

func (r *gl058) ID() string { return "GL058" }

// networkHostRe matches --network host / --net host (space or = separated).
var networkHostRe = regexp.MustCompile(`--net(?:work)?[=\s]+host(?:\s|$)`)

func (r *gl058) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerRunRe.MatchString(v) || !networkHostRe.MatchString(v) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL058",
			Severity: finding.Warn,
			Job:      job,
			Message:  "docker run --network host removes network isolation — the container shares the runner's network stack and can reach localhost services (metadata APIs, internal DBs) and bind any port; use a named network or the default bridge",
			File:     file,
			Line:     line.Line,
			Col:      line.Column,
		})
	})
	return findings
}
