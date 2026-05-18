package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl048 struct{}

var GL048 = &gl048{}

func (r *gl048) ID() string { return "GL048" }

// sshStrictHostCheckingRe matches any script line that disables SSH host key
// verification, either via command-line option (-o StrictHostKeyChecking=no/off)
// or by writing the option into an SSH config file.
var sshStrictHostCheckingRe = regexp.MustCompile(`StrictHostKeyChecking[=\s]+(no|off)\b`)

func (r *gl048) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		if sshStrictHostCheckingRe.MatchString(line.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL048",
				Severity: finding.Error,
				Job:      job,
				Message:  "StrictHostKeyChecking disabled — host identity is not verified, enabling MITM attacks on shared runner networks; use a pre-verified known_hosts entry instead",
				File:     file,
				Line:     line.Line,
				Col:      line.Column,
			})
		}
	})
	return findings
}
