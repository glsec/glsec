package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
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

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(parser.Unwrap(doc), key); node != nil {
			findings = append(findings, checkSSHRootLines(node, file, "")...)
		}
	}
	if def := parser.FindKey(parser.Unwrap(doc), "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkSSHRootLines(node, file, "")...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				for _, f := range checkSSHRootLines(node, file, "") {
					f.Job = name.Value
					findings = append(findings, f)
				}
			}
		}
	})

	return findings
}

func checkSSHRootLines(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if sshRootRe.MatchString(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL047",
				Severity: finding.Warn,
				Job:      job,
				Message:  "SSH connection as root — use a dedicated least-privilege service account instead of root to limit blast radius if the pipeline is compromised",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}
