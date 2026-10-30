// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// ContextLine is the line of the configuration WithContext adds to a
// document. A finding at or below ContextLine/2 is on that configuration;
// the file it comes from reports it itself.
const ContextLine = -1 << 20

// WithContext returns doc with the global keywords (workflow:, default:,
// variables:, stages:, …) and hidden jobs of the other files of the same
// pipeline added where doc has none (#810). GitLab merges a pipeline's
// included files into one configuration, so a job in one file is guarded by
// the workflow:rules of another and can extend its templates. The added nodes
// are copies on ContextLine, so rules read them but a finding on them is
// recognisable. Earlier documents take precedence, as the root file does in
// GitLab. doc itself is not changed; without anything to add it is returned
// as is.
func WithContext(doc *Document, others []*Document) *Document {
	mapping := doc.MappingNode()
	if mapping.Kind != yaml.MappingNode {
		return doc
	}
	have := map[string]bool{}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		have[mapping.Content[i].Value] = true
	}
	var added []*yaml.Node
	copies := map[*yaml.Node]*yaml.Node{}
	for _, o := range others {
		om := o.MappingNode()
		if om.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(om.Content); i += 2 {
			key := om.Content[i]
			if have[key.Value] || IsKeywordJob(key) || !contextKey(key.Value) {
				continue
			}
			have[key.Value] = true
			added = append(added, contextCopy(key, copies), contextCopy(om.Content[i+1], copies))
		}
	}
	if len(added) == 0 {
		return doc
	}
	merged := *mapping
	merged.Content = append(append([]*yaml.Node{}, mapping.Content...), added...)
	out := *doc
	out.Root = &merged
	return &out
}

func contextKey(name string) bool {
	return strings.HasPrefix(name, ".") || (reservedKeys[name] && name != "include")
}

// contextCopy copies n onto ContextLine. Unlike deepCopyNode it leaves the
// traced source lines behind, since they belong to the other file, and it
// copies a node shared by expanded aliases once, so the copy stays as small
// as the original.
func contextCopy(n *yaml.Node, copies map[*yaml.Node]*yaml.Node) *yaml.Node {
	if cp, ok := copies[n]; ok {
		return cp
	}
	cp := *n
	cp.Line, cp.Column = ContextLine, 0
	copies[n] = &cp
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, c := range n.Content {
			cp.Content[i] = contextCopy(c, copies)
		}
	}
	return &cp
}
