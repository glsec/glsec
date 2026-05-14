package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl021 struct{}

var GL021 = &gl021{}

func (r *gl021) ID() string { return "GL021" }

var (
	// printCmdRe matches shell output commands.
	printCmdRe = regexp.MustCompile(`\b(?:echo|printf|print)\b`)

	// secretVarRe matches CI variable references whose names end with a secret-indicating suffix.
	secretVarRe = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*(?:_TOKEN|_SECRET|_PASSWORD|_PASSWD|_PASS|_PWD|_KEY|_CREDENTIAL|_CERT)\}?`)

	// safeCheckRe matches patterns that reference the variable without printing its value:
	// length checks (-n "$VAR"), default expansions (${VAR:-}, ${VAR:+}), and masked prints.
	safeCheckRe = regexp.MustCompile(`\[\s*(?:-n|-z)\s+|:\-|:\+`)
)

func (r *gl021) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"before_script", "script", "after_script"} {
			node := parser.FindKey(job, key)
			if node == nil || node.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range node.Content {
				if item.Kind != yaml.ScalarNode {
					continue
				}
				line := item.Value
				if !printCmdRe.MatchString(line) {
					continue
				}
				match := secretVarRe.FindString(line)
				if match == "" {
					continue
				}
				// Skip lines that only check the variable's presence, not its value.
				if safeCheckRe.MatchString(line) {
					continue
				}
				findings = append(findings, finding.Finding{
					RuleID:   "GL021",
					Severity: finding.Warn,
					Message:  fmt.Sprintf("script prints secret variable %s — value may appear in job logs", match),
					File:     file,
					Line:     item.Line,
					Col:      item.Column,
				})
			}
		}
	})

	return findings
}
