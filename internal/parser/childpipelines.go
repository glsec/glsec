// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// ChildPipelinePaths returns the local file paths referenced by
// trigger: include: in any job in doc. Both forms are handled:
//
//	trigger:
//	  include: child.yml           # scalar shorthand
//
//	trigger:
//	  include:
//	    - local: child.yml         # sequence with local key
//
//	trigger:
//	  include:
//	    local: child.yml           # single mapping
//
// Multi-project triggers (trigger: project: ...) are ignored since
// there is no local file to scan.
func ChildPipelinePaths(doc *yaml.Node) []string {
	var paths []string
	for _, c := range ChildPipelines(doc) {
		paths = append(paths, c.Path)
	}
	return paths
}

// ChildPipeline is a local file a trigger job starts as a child pipeline.
type ChildPipeline struct {
	Path string
	// Waits reports that the trigger job sets trigger:strategy, so it does not
	// finish before the child pipeline does.
	Waits bool
	// Locked reports that the trigger job also sets resource_group, so GitLab
	// holds that lock until the child pipeline finishes (#1483).
	Locked bool
}

// ChildPipelines returns the child pipelines the trigger jobs of doc start,
// in the forms ChildPipelinePaths describes.
func ChildPipelines(doc *yaml.Node) []ChildPipeline {
	var children []ChildPipeline
	EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		trigger := FindKey(job, "trigger")
		if trigger == nil || trigger.Kind != yaml.MappingNode {
			return
		}
		include := FindKey(trigger, "include")
		if include == nil {
			return
		}
		waits := nonEmptyScalar(FindKey(trigger, "strategy"))
		locked := waits && nonEmptyScalar(FindKey(job, "resource_group"))
		items := []*yaml.Node{include}
		if include.Kind == yaml.SequenceNode {
			items = include.Content
		}
		for _, item := range items {
			if p := localIncludePath(item); p != "" {
				children = append(children, ChildPipeline{Path: p, Waits: waits, Locked: locked})
			}
		}
	})
	return children
}

func nonEmptyScalar(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.Value != ""
}

// localIncludePath returns the local file an include entry points at: a plain
// path string or a mapping with local:. Remote URLs and artifact:, project:,
// template: and component: entries have no local file and return "".
func localIncludePath(item *yaml.Node) string {
	switch item.Kind {
	case yaml.ScalarNode:
		if strings.Contains(item.Value, "://") {
			return ""
		}
		return item.Value
	case yaml.MappingNode:
		if local := FindKey(item, "local"); local != nil && local.Kind == yaml.ScalarNode {
			return local.Value
		}
	}
	return ""
}
