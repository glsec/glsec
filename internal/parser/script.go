// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import "gopkg.in/yaml.v3"

// maxScriptNesting caps how deep nested script lists are flattened, so a
// crafted file cannot make the recursion unbounded. Real pipelines nest one or
// two levels, from anchors.
const maxScriptNesting = 10

// NormalizeScripts rewrites every script section into the flat list of
// commands GitLab runs: a single string becomes a one-item list and nested
// lists are flattened. Rules and ShellCheck only read list items, so without
// this a job written as `script: cmd` or with `- - cmd` would not be scanned at
// all. The command nodes themselves are kept, so findings keep their lines.
func NormalizeScripts(doc *yaml.Node) {
	top := Unwrap(doc)
	if top.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(top.Content); i += 2 {
		key, value := top.Content[i].Value, top.Content[i+1]
		switch {
		case key == "before_script" || key == "after_script":
			top.Content[i+1] = scriptList(value)
		case value.Kind != yaml.MappingNode:
		case key == "default" || !reservedKeys[key]:
			normalizeContainer(value)
		}
	}
}

// normalizeContainer normalizes the script sections of a job or of default:.
func normalizeContainer(m *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		switch m.Content[i].Value {
		case "before_script", "script", "after_script":
			m.Content[i+1] = scriptList(m.Content[i+1])
		case "hooks":
			if hooks := m.Content[i+1]; hooks.Kind == yaml.MappingNode {
				for j := 0; j+1 < len(hooks.Content); j += 2 {
					if hooks.Content[j].Value == "pre_get_sources_script" {
						hooks.Content[j+1] = scriptList(hooks.Content[j+1])
					}
				}
			}
		}
	}
}

// scriptList returns the list form of a script value. An unresolved !reference
// stays as it is: its items are a path, not commands.
func scriptList(n *yaml.Node) *yaml.Node {
	switch {
	case isReference(n):
		return n
	case n.Kind == yaml.ScalarNode && n.Tag != "!!null":
		return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Line: n.Line, Column: n.Column, Content: []*yaml.Node{n}}
	case n.Kind == yaml.SequenceNode:
		n.Content = flatten(n.Content, maxScriptNesting)
	}
	return n
}

func flatten(items []*yaml.Node, depth int) []*yaml.Node {
	nested := false
	for _, item := range items {
		if item.Kind == yaml.SequenceNode && !isReference(item) {
			nested = true
			break
		}
	}
	if !nested || depth == 0 {
		return items
	}
	out := make([]*yaml.Node, 0, len(items))
	for _, item := range items {
		if item.Kind == yaml.SequenceNode && !isReference(item) {
			out = append(out, flatten(item.Content, depth-1)...)
		} else {
			out = append(out, item)
		}
	}
	return out
}
