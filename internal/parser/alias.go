// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

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
//
// It returns the keys written on a mapping that a later << overrides.
func ExpandAliases(node *yaml.Node) []DuplicateKey {
	if node == nil {
		return nil
	}
	e := &expander{done: map[*yaml.Node]bool{}, onPath: map[*yaml.Node]bool{}, sizes: map[*yaml.Node]int{}, root: Unwrap(node)}
	e.expand(node)
	return e.overridden
}

type expander struct {
	done   map[*yaml.Node]bool
	onPath map[*yaml.Node]bool
	sizes  map[*yaml.Node]int
	used   int
	root   *yaml.Node // the top-level mapping
	job    string     // the top-level key being expanded
	// overridden lists the own keys a << replaced.
	overridden []DuplicateKey
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
			if node == e.root {
				e.job = node.Content[i-1].Value
			}
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

// foldMergeKeys replaces a mapping's << entries with the keys they merge in,
// the way GitLab's YAML loader, Ruby's Psych, reads a mapping: entry by entry.
// A << overrides the keys written before it and a key written after it
// overrides the <<, unlike the YAML merge-key spec, where own keys always win
// (#1152). A key keeps the position it was first set at, and an own key a <<
// overrides is recorded in overridden. A source that stayed an alias (a cycle,
// or over budget) keeps its << entry unfolded.
func (e *expander) foldMergeKeys(node *yaml.Node) {
	hasMerge := false
	for i := 0; i+1 < len(node.Content); i += 2 {
		hasMerge = hasMerge || node.Content[i].Tag == "!!merge"
	}
	if !hasMerge {
		return
	}
	out := make([]*yaml.Node, 0, len(node.Content))
	at := map[dupID]int{} // where each key sits in out
	own := map[int]bool{} // positions in out written on this mapping itself
	put := func(key, value *yaml.Node) int {
		id, ok := keyID(key)
		if pos, seen := at[id]; ok && seen {
			out[pos], out[pos+1] = key, value
			return pos
		}
		if ok {
			at[id] = len(out)
		}
		out = append(out, key, value)
		return len(out) - 2
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Tag != "!!merge" {
			own[put(key, value)] = true
			continue
		}
		merged, complete := mergedEntries(value)
		for j := 0; j+1 < len(merged); j += 2 {
			if id, ok := keyID(merged[j]); ok {
				if pos, seen := at[id]; seen && own[pos] {
					e.reportOverride(node, out[pos], out[pos+1], merged[j], key)
					delete(own, pos)
				}
			}
			put(merged[j], merged[j+1])
		}
		if !complete {
			out = append(out, key, value)
		}
	}
	node.Content = out
}

// mergedEntries returns the key/value pairs a << value merges in. In a list
// earlier sources win, and, as in Psych, the last source's keys come first.
// complete is false when a source isn't a mapping: resolve kept it an alias.
func mergedEntries(value *yaml.Node) (entries []*yaml.Node, complete bool) {
	sources := []*yaml.Node{value}
	if value.Kind == yaml.SequenceNode {
		sources = value.Content
	}
	complete = true
	at := map[dupID]int{}
	for i := len(sources) - 1; i >= 0; i-- {
		src := sources[i]
		if src.Kind != yaml.MappingNode {
			complete = false
			continue
		}
		for j := 0; j+1 < len(src.Content); j += 2 {
			key, val := src.Content[j], src.Content[j+1]
			id, ok := keyID(key)
			if pos, seen := at[id]; ok && seen {
				entries[pos], entries[pos+1] = key, val
				continue
			}
			if ok {
				at[id] = len(entries)
			}
			entries = append(entries, key, val)
		}
	}
	return entries, complete
}

// reportOverride records an own key whose value a << replaced.
func (e *expander) reportOverride(node, key, value, winner, merge *yaml.Node) {
	job := e.job
	if node == e.root {
		job = key.Value
	}
	if reservedKeys[job] {
		job = ""
	}
	e.overridden = append(e.overridden, DuplicateKey{Key: key, Winner: winner, Merge: merge, Job: job, Anchor: firstAnchor(value)})
}

func deref(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}
	return node
}
