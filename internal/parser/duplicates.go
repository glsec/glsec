// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import "gopkg.in/yaml.v3"

// DuplicateKey is a mapping key that appears again later in the same mapping.
// GitLab loads the file with Ruby's YAML.safe_load, where the later entry
// overwrites the earlier one without an error.
type DuplicateKey struct {
	// Key is the earlier key, whose value GitLab ignores.
	Key *yaml.Node
	// Winner is the last key with the same name, whose value GitLab uses.
	Winner *yaml.Node
	// Job is the top-level key the duplicate sits under, or the duplicated
	// top-level key itself; empty for reserved keys such as variables:.
	Job string
	// Anchor is the anchor on the ignored value, if any. Aliases of it still
	// use the value, so only the key is dead.
	Anchor string
}

// CollapseDuplicateKeys removes every key that appears again later in the
// same mapping, with its value, so that the tree holds what GitLab runs: the
// last value, at its own position (#633). It returns the removed keys. Merge
// keys (<<) are left alone; ExpandAliases lets explicit keys override them
// whatever their order. It must run before ExpandAliases, so that an anchor is
// collapsed once and every alias of it sees the result.
// firstAnchor returns the anchor on n or, depth first, on a node inside it
// (#1005): an alias of a nested anchor still uses that part of the value.
func firstAnchor(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Anchor != "" {
		return n.Anchor
	}
	for _, c := range n.Content {
		if a := firstAnchor(c); a != "" {
			return a
		}
	}
	return ""
}

func CollapseDuplicateKeys(doc *yaml.Node) []DuplicateKey {
	if doc == nil {
		return nil
	}
	var dups []DuplicateKey
	under := func(job string) func(key, value, winner *yaml.Node) {
		if reservedKeys[job] {
			job = ""
		}
		return func(key, value, winner *yaml.Node) {
			dups = append(dups, DuplicateKey{Key: key, Winner: winner, Job: job, Anchor: firstAnchor(value)})
		}
	}
	top := Unwrap(doc)
	if top.Kind != yaml.MappingNode {
		walkCollapse(top, under(""))
		return dups
	}
	collapse(top, func(key, value, winner *yaml.Node) { under(key.Value)(key, value, winner) })
	for i := 0; i+1 < len(top.Content); i += 2 {
		walkCollapse(top.Content[i+1], under(top.Content[i].Value))
	}
	return dups
}

// walkCollapse collapses node and everything below it. Alias nodes are not
// followed: their anchor is collapsed where it is defined.
func walkCollapse(node *yaml.Node, report func(key, value, winner *yaml.Node)) {
	if node == nil {
		return
	}
	collapse(node, report)
	for _, child := range node.Content {
		walkCollapse(child, report)
	}
}

// collapse removes the duplicate keys of a single mapping.
func collapse(m *yaml.Node, report func(key, value, winner *yaml.Node)) {
	if m.Kind != yaml.MappingNode {
		return
	}
	last := map[dupID]int{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if id, ok := keyID(m.Content[i]); ok {
			last[id] = i
		}
	}
	if len(last) == len(m.Content)/2 {
		return
	}
	out := m.Content[:0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, value := m.Content[i], m.Content[i+1]
		if id, ok := keyID(key); ok && last[id] != i {
			report(key, value, m.Content[last[id]])
			continue
		}
		out = append(out, key, value)
	}
	m.Content = out
}

// dupID identifies a key the way Ruby compares hash keys after loading: by
// its value and type, so 1 and "1" are different keys.
type dupID struct{ tag, value string }

func keyID(key *yaml.Node) (dupID, bool) {
	if key.Kind != yaml.ScalarNode {
		return dupID{}, false
	}
	tag := key.ShortTag()
	if tag == "!!merge" {
		return dupID{}, false
	}
	return dupID{tag, key.Value}, true
}
