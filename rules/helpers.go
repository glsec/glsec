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

// hookScriptNode returns the hooks:pre_get_sources_script sequence node for a
// job or default: mapping, or nil. These commands run on the runner before the
// repository is cloned, so they are script lines that security rules must scan.
func hookScriptNode(container *yaml.Node) *yaml.Node {
	hooks := parser.FindKey(container, "hooks")
	if hooks == nil {
		return nil
	}
	return parser.FindKey(hooks, "pre_get_sources_script")
}

// CollectJobScriptLines returns all scalar script lines from a job's
// before_script, script, after_script, and hooks:pre_get_sources_script sections.
func CollectJobScriptLines(job *yaml.Node) []*yaml.Node {
	var lines []*yaml.Node
	appendScalars := func(node *yaml.Node) {
		if node == nil || node.Kind != yaml.SequenceNode {
			return
		}
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				lines = append(lines, item)
			}
		}
	}
	for _, key := range []string{"before_script", "script", "after_script"} {
		appendScalars(parser.FindKey(job, key))
	}
	appendScalars(hookScriptNode(job))
	return lines
}

// EachScriptBlock visits every script *sequence node* in the document: global
// before/after_script, default: before/after_script + hooks:pre_get_sources_script,
// and each job's script/before_script/after_script + hooks:pre_get_sources_script.
// fn receives the sequence node, the file path, and the job name (empty for
// global and default: blocks). hooks: is not a valid top-level keyword, so it is
// only visited under default: and jobs.
func EachScriptBlock(doc *yaml.Node, file string, fn func(node *yaml.Node, file, job string)) {
	mapping := parser.Unwrap(doc)

	visit := func(node *yaml.Node, job string) {
		if node != nil && node.Kind == yaml.SequenceNode {
			fn(node, file, job)
		}
	}

	for _, key := range []string{"before_script", "after_script"} {
		visit(parser.FindKey(mapping, key), "")
	}

	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			visit(parser.FindKey(def, key), "")
		}
		visit(hookScriptNode(def), "")
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			visit(parser.FindKey(job, key), name.Value)
		}
		visit(hookScriptNode(job), name.Value)
	})
}

// EachScriptLine visits every scalar script line in the document, calling fn
// for each. It covers the same blocks as EachScriptBlock (global, default:, and
// per-job script sections, including hooks:pre_get_sources_script).
// fn receives the line node, the file path, and the job name (empty for
// global and default: sections).
func EachScriptLine(doc *yaml.Node, file string, fn func(line *yaml.Node, file, job string)) {
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				fn(item, file, job)
			}
		}
	})
}
