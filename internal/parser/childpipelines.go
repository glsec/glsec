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
	EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		trigger := FindKey(job, "trigger")
		if trigger == nil || trigger.Kind != yaml.MappingNode {
			return
		}
		include := FindKey(trigger, "include")
		if include == nil {
			return
		}
		items := []*yaml.Node{include}
		if include.Kind == yaml.SequenceNode {
			items = include.Content
		}
		for _, item := range items {
			if p := localIncludePath(item); p != "" {
				paths = append(paths, p)
			}
		}
	})
	return paths
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
