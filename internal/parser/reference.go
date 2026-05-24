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
// https://docs.gitlab.com/ci/yaml/yaml_optimization/#reference-tags
func ResolveReferences(doc *yaml.Node) {
	top := doc
	if top.Kind == yaml.DocumentNode && len(top.Content) > 0 {
		top = top.Content[0]
	}
	if top.Kind != yaml.MappingNode {
		return
	}
	expand(top, top, nil)
}

func isReference(n *yaml.Node) bool {
	return n != nil && n.Tag == referenceTag
}

// expand walks node, resolving any !reference descendants. top is the document's
// root mapping used for path lookups; active is the chain of reference paths
// currently being resolved, used for cycle detection.
func expand(node, top *yaml.Node, active []string) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			if v := node.Content[i]; isReference(v) {
				if resolved := resolveReference(v, top, active); resolved != nil {
					node.Content[i] = resolved
				}
			} else {
				expand(node.Content[i], top, active)
			}
		}
	case yaml.SequenceNode:
		out := make([]*yaml.Node, 0, len(node.Content))
		for _, item := range node.Content {
			if !isReference(item) {
				expand(item, top, active)
				out = append(out, item)
				continue
			}
			resolved := resolveReference(item, top, active)
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
// ref, or nil if the path cannot be resolved or would form a cycle.
func resolveReference(ref, top *yaml.Node, active []string) *yaml.Node {
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

	target := lookupPath(top, segs)
	if target == nil {
		return nil
	}

	cp := deepCopyNode(target)
	next := make([]string, len(active), len(active)+1)
	copy(next, active)
	next = append(next, key)
	expand(cp, top, next)
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

func deepCopyNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	cp := *n
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, c := range n.Content {
			cp.Content[i] = deepCopyNode(c)
		}
	}
	return &cp
}
