package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl017 struct{}

var GL017 = &gl017{}

func (r *gl017) ID() string { return "GL017" }

// deployStageKeywords identifies stages that indicate deployment activity.
var deployStageKeywords = []string{"deploy", "release", "publish", "ship"}

func (r *gl017) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !isSensitiveJob(job) {
			return
		}
		tagsNode := parser.FindKey(job, "tags")
		if tagsNode != nil && tagsNode.Kind == yaml.SequenceNode && len(tagsNode.Content) > 0 {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL017",
			Severity: finding.Warn,
			Message: fmt.Sprintf(
				"job %q deploys or publishes but has no tags: — it can run on any available runner, including untrusted self-hosted runners",
				name.Value,
			),
			File: file,
			Line: name.Line,
			Col:  name.Column,
		})
	})

	return findings
}

// isSensitiveJob returns true for jobs that deploy to an environment or
// whose stage name suggests deployment/release activity.
func isSensitiveJob(job *yaml.Node) bool {
	if parser.FindKey(job, "environment") != nil {
		return true
	}
	stageNode := parser.FindKey(job, "stage")
	if stageNode != nil && stageNode.Kind == yaml.ScalarNode {
		lower := strings.ToLower(stageNode.Value)
		for _, kw := range deployStageKeywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
	}
	return false
}
