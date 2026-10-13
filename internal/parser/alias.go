package parser

import "gopkg.in/yaml.v3"

// maxExpandedNodes caps how many nodes alias expansion may add to the tree.
// Expansion reuses nodes, but rules walk every path through them, so nested
// aliases ("billion laughs") would otherwise make a scan exponentially slow.
// Real pipelines stay far below it.
const maxExpandedNodes = 250_000

// ExpandAliases replaces YAML aliases (*name) with the nodes their anchors
// name and folds merge keys (<<: *name, <<: [*a, *b]) into the mapping that
// holds them, so rules see a job's configuration however it was written.
//
// The anchored nodes are reused, not copied: a finding in expanded content
// points at the anchor's line, and content shared by several jobs is the same
// node in each of them. A list alias inside a list is spliced in, as GitLab
// flattens nested lists in script: and similar keys.
//
// Two kinds of alias stay unexpanded, as they were before expansion existed:
// one that points at an enclosing node, which would make the tree cyclic, and
// any alias past the maxExpandedNodes budget.
func ExpandAliases(node *yaml.Node) {
	e := &expander{done: map[*yaml.Node]bool{}, onPath: map[*yaml.Node]bool{}, sizes: map[*yaml.Node]int{}}
	e.expand(node)
}

type expander struct {
	done   map[*yaml.Node]bool
	onPath map[*yaml.Node]bool
	sizes  map[*yaml.Node]int
	used   int
}

func (e *expander) expand(node *yaml.Node) {
	if node == nil || e.done[node] {
		return
	}
	e.done[node] = true
	e.onPath[node] = true
	defer delete(e.onPath, node)

	switch node.Kind {
	case yaml.DocumentNode:
		for i, child := range node.Content {
			node.Content[i] = e.resolve(child)
		}
	case yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			node.Content[i] = e.resolve(node.Content[i])
		}
		e.foldMergeKeys(node)
	case yaml.SequenceNode:
		out := make([]*yaml.Node, 0, len(node.Content))
		for _, item := range node.Content {
			resolved := e.resolve(item)
			if item.Kind == yaml.AliasNode && resolved.Kind == yaml.SequenceNode {
				out = append(out, resolved.Content...)
			} else {
				out = append(out, resolved)
			}
		}
		node.Content = out
	}
}

// resolve expands node and returns what should take its place: the anchored
// node for an alias that may be expanded, the node itself otherwise.
func (e *expander) resolve(node *yaml.Node) *yaml.Node {
	if node.Kind != yaml.AliasNode {
		e.expand(node)
		return node
	}
	target := deref(node)
	if target == nil || e.onPath[target] {
		return node // a cycle: keep the alias
	}
	e.expand(target)
	if !e.spend(target) {
		return node
	}
	return target
}

// spend charges the size of the subtree an alias adds and reports whether it
// still fits in the budget.
func (e *expander) spend(target *yaml.Node) bool {
	n := e.size(target)
	if e.used+n > maxExpandedNodes {
		return false
	}
	e.used += n
	return true
}

// size counts the nodes a walk over node visits, shared subtrees once per
// path, capped just above the budget.
func (e *expander) size(node *yaml.Node) int {
	if n, ok := e.sizes[node]; ok {
		return n
	}
	n := 1
	if node.Kind != yaml.AliasNode {
		for _, child := range node.Content {
			if n += e.size(child); n > maxExpandedNodes {
				n = maxExpandedNodes + 1
				break
			}
		}
	}
	e.sizes[node] = n
	return n
}

// foldMergeKeys replaces a mapping's << entries with the keys they merge in.
// Keys set directly on the mapping win, and earlier merge sources win over
// later ones, as the YAML merge-key spec defines. A source that stayed an
// alias (a cycle, or over budget) keeps its << entry unfolded.
func (e *expander) foldMergeKeys(node *yaml.Node) {
	var merges []*yaml.Node
	own := make([]*yaml.Node, 0, len(node.Content))
	present := map[string]bool{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Tag == "!!merge" {
			merges = append(merges, key, value)
			continue
		}
		own = append(own, key, value)
		present[key.Value] = true
	}
	if merges == nil {
		return
	}
	for i := 0; i < len(merges); i += 2 {
		sources := []*yaml.Node{merges[i+1]}
		if merges[i+1].Kind == yaml.SequenceNode {
			sources = merges[i+1].Content
		}
		for _, src := range sources {
			// resolve already expanded the << value, or kept it an alias.
			if src.Kind != yaml.MappingNode {
				own = append(own, merges[i], merges[i+1])
				break
			}
			for j := 0; j+1 < len(src.Content); j += 2 {
				key := src.Content[j]
				if present[key.Value] {
					continue
				}
				present[key.Value] = true
				own = append(own, key, src.Content[j+1])
			}
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
