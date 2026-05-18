package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl047 struct{}

var GL047 = &gl047{}

func (r *gl047) ID() string { return "GL047" }

// sshRootRe matches an ssh invocation with root as the login user.
// It allows arbitrary flags between ssh and root@ to cover common forms like
// ssh -i key root@host, ssh -p 2222 root@host, ssh -o ... root@host.
var sshRootRe = regexp.MustCompile(`\bssh\b.*\broot@`)

func (r *gl047) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		if sshRootRe.MatchString(line.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL047",
				Severity: finding.Warn,
				Job:      job,
				Message:  "SSH connection as root — use a dedicated least-privilege service account instead of root to limit blast radius if the pipeline is compromised",
				File:     file,
				Line:     line.Line,
				Col:      line.Column,
			})
		}
	})
	return findings
}
