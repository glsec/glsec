package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl044 struct{}

var GL044 = &gl044{}

func (r *gl044) ID() string { return "GL044" }

// mrSourceSHARe matches any reference to CI_MERGE_REQUEST_SOURCE_BRANCH_SHA.
var mrSourceSHARe = regexp.MustCompile(`\$\{?CI_MERGE_REQUEST_SOURCE_BRANCH_SHA\}?`)

func (r *gl044) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !jobHasMRTrigger(job) {
			return
		}

		for _, key := range []string{"script", "before_script"} {
			node := parser.FindKey(job, key)
			if node == nil {
				continue
			}
			for _, f := range checkScriptForMRSourceSHA(node, file) {
				f.Job = name.Value
				findings = append(findings, f)
			}
		}
		if h := hookScriptNode(job); h != nil {
			for _, f := range checkScriptForMRSourceSHA(h, file) {
				f.Job = name.Value
				findings = append(findings, f)
			}
		}

		if imageNode := parser.FindKey(job, "image"); imageNode != nil {
			if f := checkImageForMRSourceSHA(imageNode, file, name.Value); f != nil {
				findings = append(findings, *f)
			}
		}
	})

	return findings
}

// jobHasMRTrigger returns true if the job is triggered on merge request events,
// either via the legacy only: syntax or via rules:if conditions.
func jobHasMRTrigger(job *yaml.Node) bool {
	if onlyNode := parser.FindKey(job, "only"); onlyNode != nil && onlyNode.Kind == yaml.SequenceNode {
		for _, item := range onlyNode.Content {
			if item.Kind == yaml.ScalarNode && item.Value == "merge_requests" {
				return true
			}
		}
	}

	rulesNode := parser.FindKey(job, "rules")
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rulesNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
			continue
		}
		if strings.Contains(ifNode.Value, "merge_request") {
			return true
		}
	}
	return false
}

func checkScriptForMRSourceSHA(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if mrSourceSHARe.MatchString(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL044",
				Severity: finding.Warn,
				Message:  "MR-triggered job checks out $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA — executes attacker-controlled code with access to $CI_JOB_TOKEN and protected variables",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}

func checkImageForMRSourceSHA(node *yaml.Node, file, job string) *finding.Finding {
	var imageValue string
	switch node.Kind {
	case yaml.ScalarNode:
		imageValue = node.Value
	case yaml.MappingNode:
		if nameNode := parser.FindKey(node, "name"); nameNode != nil && nameNode.Kind == yaml.ScalarNode {
			imageValue = nameNode.Value
			node = nameNode
		}
	}
	if !mrSourceSHARe.MatchString(imageValue) {
		return nil
	}
	f := finding.Finding{
		RuleID:   "GL044",
		Severity: finding.Warn,
		Job:      job,
		Message:  "MR-triggered job uses $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA in image: — pulls an attacker-controlled container image",
		File:     file,
		Line:     node.Line,
		Col:      node.Column,
	}
	return &f
}
