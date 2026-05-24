package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl062 struct{}

var GL062 = &gl062{}

func (r *gl062) ID() string { return "GL062" }

// envFullDumpRe matches a standalone `printenv` or `env` command (optionally
// path-prefixed) with no arguments — i.e. one that dumps the entire
// environment. The command must sit at a shell command boundary and be
// followed immediately by end-of-line or a shell separator, so
// `printenv VAR` and `env VAR=v cmd` are not matched.
var envFullDumpRe = regexp.MustCompile(`(?:^|[;&|(])\s*(?:/usr/bin/|/bin/)?(?:printenv|env)\s*(?:$|[;&|#)])`)

func (r *gl062) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !envFullDumpRe.MatchString(v) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL062",
			Severity: finding.Warn,
			Job:      job,
			Message:  "printenv/env with no arguments dumps every environment variable to the job log, including CI/CD secrets and tokens that may not be reliably masked — print only the specific variables you need",
			File:     file,
			Line:     line.Line,
			Col:      line.Column,
		})
	})
	return findings
}
