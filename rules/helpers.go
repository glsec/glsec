package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// deployLikeKeywords covers job and stage names that indicate deployment,
// release, or artifact publishing activity.
var deployLikeKeywords = []string{
	"deploy", "release", "publish", "rollout",
	"migrat", "provision", "ship", "push", "upload", "dist",
}

// IsDeployLikeJob returns true when the job name, stage name, or presence of
// an environment: key indicates deployment, release, or artifact publishing.
// Used by rules that need to identify jobs that mutate external state.
func IsDeployLikeJob(jobName string, job *yaml.Node) bool {
	lower := strings.ToLower(jobName)
	for _, kw := range deployLikeKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	if parser.FindKey(job, "environment") != nil {
		return true
	}
	if stageNode := parser.FindKey(job, "stage"); stageNode != nil && stageNode.Kind == yaml.ScalarNode {
		stageLower := strings.ToLower(stageNode.Value)
		for _, kw := range deployLikeKeywords {
			if strings.Contains(stageLower, kw) {
				return true
			}
		}
	}
	return false
}

// CollectJobScriptLines returns all scalar script lines from a job's
// before_script, script, and after_script sections.
func CollectJobScriptLines(job *yaml.Node) []*yaml.Node {
	var lines []*yaml.Node
	for _, key := range []string{"before_script", "script", "after_script"} {
		node := parser.FindKey(job, key)
		if node == nil || node.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				lines = append(lines, item)
			}
		}
	}
	return lines
}

// EachScriptLine visits every scalar script line in the document, calling fn
// for each. It covers global before/after_script, default: before/after_script,
// and all job-level script/before_script/after_script sections.
// fn receives the line node, the file path, and the job name (empty for
// global and default: sections).
func EachScriptLine(doc *yaml.Node, file string, fn func(line *yaml.Node, file, job string)) {
	mapping := parser.Unwrap(doc)

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil && node.Kind == yaml.SequenceNode {
			for _, item := range node.Content {
				if item.Kind == yaml.ScalarNode {
					fn(item, file, "")
				}
			}
		}
	}

	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil && node.Kind == yaml.SequenceNode {
				for _, item := range node.Content {
					if item.Kind == yaml.ScalarNode {
						fn(item, file, "")
					}
				}
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil && node.Kind == yaml.SequenceNode {
				for _, item := range node.Content {
					if item.Kind == yaml.ScalarNode {
						fn(item, file, name.Value)
					}
				}
			}
		}
	})
}
