package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl014 struct{}

var GL014 = &gl014{}

func (r *gl014) ID() string { return "GL014" }

// envDumpRe matches script lines that redirect the full environment to a file:
// "env > file", "env > file", "printenv > file".
// Does not match "printenv VAR > file" (single-var export) or "env | grep ... > file".
var envDumpRe = regexp.MustCompile(`\benv\s*>|\bprintenv\s*>`)

func (r *gl014) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		dotenvNode := dotenvArtifactNode(job)
		if dotenvNode == nil {
			return
		}
		// Check all script blocks for an env dump line.
		scriptNodes := []*yaml.Node{
			parser.FindKey(job, "script"),
			parser.FindKey(job, "before_script"),
			parser.FindKey(job, "after_script"),
			hookScriptNode(job),
		}
		for _, scriptNode := range scriptNodes {
			if scriptNode == nil || scriptNode.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range scriptNode.Content {
				if item.Kind != yaml.ScalarNode {
					continue
				}
				if envDumpRe.MatchString(item.Value) {
					findings = append(findings, finding.Finding{
						RuleID:   "GL014",
						Severity: finding.Warn,
						Job:      name.Value,
						Message: fmt.Sprintf(
							"job %q dumps all environment variables to a dotenv artifact — CI_JOB_TOKEN and masked secrets are included and downloadable by any pipeline viewer",
							name.Value,
						),
						File: file,
						Line: item.Line,
						Col:  item.Column,
					})
					return // one finding per job is enough
				}
			}
		}
	})

	return findings
}

// dotenvArtifactNode returns the dotenv value node if the job has
// artifacts.reports.dotenv set, otherwise nil.
func dotenvArtifactNode(job *yaml.Node) *yaml.Node {
	artifacts := parser.FindKey(job, "artifacts")
	if artifacts == nil {
		return nil
	}
	reports := parser.FindKey(artifacts, "reports")
	if reports == nil {
		return nil
	}
	return parser.FindKey(reports, "dotenv")
}
