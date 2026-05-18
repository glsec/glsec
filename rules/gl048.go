package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
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

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(parser.Unwrap(doc), key); node != nil {
			findings = append(findings, checkStrictHostCheckingLines(node, file, "")...)
		}
	}
	if def := parser.FindKey(parser.Unwrap(doc), "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkStrictHostCheckingLines(node, file, "")...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				for _, f := range checkStrictHostCheckingLines(node, file, "") {
					f.Job = name.Value
					findings = append(findings, f)
				}
			}
		}
	})

	return findings
}

func checkStrictHostCheckingLines(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if sshStrictHostCheckingRe.MatchString(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL048",
				Severity: finding.Error,
				Job:      job,
				Message:  "StrictHostKeyChecking disabled — host identity is not verified, enabling MITM attacks on shared runner networks; use a pre-verified known_hosts entry instead",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}
