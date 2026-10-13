package parser

import "gopkg.in/yaml.v3"

// ExpandAliases replaces YAML aliases (*name) with the nodes their anchors
// name and folds merge keys (<<: *name, <<: [*a, *b]) into the mapping that
// holds them, so rules see a job's configuration however it was written.
//
// The anchored nodes are reused, not copied: a finding in expanded content
// points at the anchor's line, and content shared by several jobs is the same
// node in each of them. A list alias inside a list is spliced in, as GitLab
// flattens nested lists in script: and similar keys.
func ExpandAliases(node *yaml.Node) {
	expandAliases(node, map[*yaml.Node]bool{})
}

func expandAliases(node *yaml.Node, done map[*yaml.Node]bool) {
	if node == nil || done[node] {
		return
	}
	done[node] = true
	switch node.Kind {
	case yaml.DocumentNode:
		for i, child := range node.Content {
			node.Content[i] = deref(child)
			expandAliases(node.Content[i], done)
		}
	case yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			node.Content[i] = deref(node.Content[i])
			expandAliases(node.Content[i], done)
		}
		foldMergeKeys(node)
	case yaml.SequenceNode:
		out := make([]*yaml.Node, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.AliasNode {
				expandAliases(item, done)
				out = append(out, item)
				continue
			}
			target := deref(item)
			expandAliases(target, done)
			if target != nil && target.Kind == yaml.SequenceNode {
				out = append(out, target.Content...)
			} else {
				out = append(out, target)
			}
		}
		node.Content = out
	}
}

// foldMergeKeys replaces a mapping's << entries with the keys they merge in.
// Keys set directly on the mapping win, and earlier merge sources win over
// later ones, as the YAML merge-key spec defines.
func foldMergeKeys(node *yaml.Node) {
	var sources []*yaml.Node
	own := make([]*yaml.Node, 0, len(node.Content))
	present := map[string]bool{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Tag == "!!merge" {
			if value.Kind == yaml.SequenceNode {
				sources = append(sources, value.Content...)
			} else {
				sources = append(sources, value)
			}
			continue
		}
		own = append(own, key, value)
		present[key.Value] = true
	}
	if sources == nil {
		return
	}
	for _, src := range sources {
		src = deref(src)
		if src == nil || src.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(src.Content); i += 2 {
			key := src.Content[i]
			if present[key.Value] {
				continue
			}
			present[key.Value] = true
			own = append(own, key, src.Content[i+1])
		}
	}
	node.Content = own
}

func deref(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}
