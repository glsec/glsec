// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"

	"gopkg.in/yaml.v3"
)

const referenceTag = "!reference"

// ResolveReferences expands GitLab CI `!reference [a, b, …]` tags in place,
// inlining same-file referenced content so downstream rules see it. References
// that cannot be resolved within this document (e.g. they target content from
// an include:) are left untouched. Circular references are detected and left
// unresolved rather than recursing forever.
//
// Each resolved reference is a copy, so nested references multiply the tree
// the way nested aliases do. Copies share the maxExpandedNodes budget; once it
// is spent, the remaining references stay unresolved.
//
// https://docs.gitlab.com/ci/yaml/yaml_optimization/#reference-tags
func ResolveReferences(doc *yaml.Node) {
	top := doc
	if top.Kind == yaml.DocumentNode && len(top.Content) > 0 {
		top = top.Content[0]
	}
	if top.Kind != yaml.MappingNode {
		return
	}
	r := &resolver{top: top, left: maxExpandedNodes}
	r.expand(top, nil)
}

type resolver struct {
	top  *yaml.Node
	left int
}

func isReference(n *yaml.Node) bool {
	return n != nil && n.Tag == referenceTag
}

// IsReference reports whether n is a !reference that could not be resolved
// within the file. Its items are the path, not content, so code that reads
// script lists must skip it (#746).
func IsReference(n *yaml.Node) bool { return isReference(n) }

// expand walks node, resolving any !reference descendants. active is the chain
// of reference paths currently being resolved, used for cycle detection.
func (r *resolver) expand(node *yaml.Node, active []string) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			if v := node.Content[i]; isReference(v) {
				if resolved := r.resolveReference(v, active); resolved != nil {
					node.Content[i] = resolved
				}
			} else {
				r.expand(node.Content[i], active)
			}
		}
	case yaml.SequenceNode:
		out := make([]*yaml.Node, 0, len(node.Content))
		for _, item := range node.Content {
			if !isReference(item) {
				r.expand(item, active)
				out = append(out, item)
				continue
			}
			resolved := r.resolveReference(item, active)
			switch {
			case resolved == nil:
				out = append(out, item) // unresolvable — leave as-is
			case resolved.Kind == yaml.SequenceNode:
				out = append(out, resolved.Content...) // flatten into parent list
			default:
				out = append(out, resolved)
			}
		}
		node.Content = out
	}
}

// resolveReference returns a fully-resolved deep copy of the node referenced by
// ref, or nil if the path cannot be resolved, would form a cycle or would
// exceed the budget.
func (r *resolver) resolveReference(ref *yaml.Node, active []string) *yaml.Node {
	segs := make([]string, 0, len(ref.Content))
	for _, c := range ref.Content {
		if c.Kind != yaml.ScalarNode {
			return nil
		}
		segs = append(segs, c.Value)
	}
	if len(segs) == 0 {
		return nil
	}

	key := strings.Join(segs, "\x00")
	for _, a := range active {
		if a == key {
			return nil // circular reference
		}
	}

	target := lookupPath(r.top, segs)
	if target == nil {
		return nil
	}
	n := countNodes(target, r.left)
	if n > r.left {
		r.left = 0
		return nil
	}
	r.left -= n

	cp := deepCopyNode(target)
	next := make([]string, len(active), len(active)+1)
	copy(next, active)
	next = append(next, key)
	r.expand(cp, next)
	return cp
}

// lookupPath navigates the path segments from the root mapping.
func lookupPath(top *yaml.Node, segs []string) *yaml.Node {
	cur := top
	for _, s := range segs {
		if cur.Kind != yaml.MappingNode {
			return nil
		}
		v := FindKey(cur, s)
		if v == nil {
			return nil
		}
		cur = v
	}
	return cur
}

// countNodes returns the number of nodes in the tree under n, or limit+1 as
// soon as it is larger than limit.
func countNodes(n *yaml.Node, limit int) int {
	count := 1
	for _, c := range n.Content {
		if count += countNodes(c, limit-count); count > limit {
			return limit + 1
		}
	}
	return count
}

func deepCopyNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	cp := *n
	copyScalarLines(n, &cp)
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, c := range n.Content {
			cp.Content[i] = deepCopyNode(c)
		}
	}
	return &cp
}
