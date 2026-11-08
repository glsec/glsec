// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContextLine is the line of the configuration WithContext adds to a
// document. A finding at or below ContextLine/2 is on that configuration;
// the file it comes from reports it itself.
const ContextLine = -1 << 20

// IsContextLine reports whether a line is on configuration from another file.
func IsContextLine(line int) bool {
	return line <= ContextLine/2
}

// contextFile is a file WithContext copied nodes from: a copy of its line n
// sits on ContextLine + base + n.
type contextFile struct {
	file string
	base int
}

// ContextOrigin returns the file and line a context line stands for, if known.
func (d *Document) ContextOrigin(line int) (file string, at int, ok bool) {
	rel := line - ContextLine
	for _, f := range slices.Backward(d.contextFiles) {
		if rel > f.base {
			return f.file, rel - f.base, true
		}
	}
	return "", 0, false
}

// WithContext returns doc as GitLab merges it into its pipeline (#810): the
// global keywords (workflow:, default:, variables:, stages:, …) and hidden jobs
// of the other files are added, and the jobs doc shares with them merged. So a
// job in one file is guarded by the workflow:rules of another, can extend its
// templates, and doesn't count a value another file overrides. A job doc
// doesn't define stays out: its file reports it.
//
// pipeline lists the pipeline's files in merge order (see MergeOrder), doc
// among them. Mappings merge at any depth and everything else is replaced, so
// the last file that sets a value wins. Nodes from another file are copies on
// ContextLine: rules read them, but each node keeps exactly one file that
// reports it, including a mapping or a key several files set, which belongs to
// the last of them. doc itself is not changed; without anything to add it is
// returned as is.
func WithContext(doc *Document, pipeline []*Document) *Document {
	mapping := doc.MappingNode()
	if mapping.Kind != yaml.MappingNode {
		return doc
	}
	own := map[string]bool{}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		own[mapping.Content[i].Value] = true
	}
	m := contextMerge{copies: map[*yaml.Node]*yaml.Node{}, merged: map[[2]*yaml.Node]*yaml.Node{}}
	var files []contextFile
	result := map[string]int{}
	var keys, values []*yaml.Node
	for _, o := range pipeline {
		om := o.MappingNode()
		if om.Kind != yaml.MappingNode {
			continue
		}
		m.own = o == doc
		if !m.own {
			m.base += m.last
			m.last = 0
			files = append(files, contextFile{o.File, m.base})
		}
		for i := 0; i+1 < len(om.Content); i += 2 {
			key := om.Content[i]
			if !m.own && (IsKeywordJob(key) || !contextKey(key.Value) && (!own[key.Value] || reservedKeys[key.Value])) {
				continue
			}
			if at, ok := result[key.Value]; ok {
				keys[at], values[at] = m.node(key), m.over(values[at], om.Content[i+1])
				continue
			}
			result[key.Value] = len(keys)
			keys, values = append(keys, m.node(key)), append(values, m.node(om.Content[i+1]))
		}
	}
	if !m.foreign {
		return doc
	}
	merged := *mapping
	merged.Content = make([]*yaml.Node, 0, 2*len(keys))
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		at := result[mapping.Content[i].Value]
		merged.Content = append(merged.Content, keys[at], values[at])
	}
	for i, key := range keys {
		if !own[key.Value] {
			merged.Content = append(merged.Content, key, values[i])
		}
	}
	out := *doc
	out.Root = &merged
	out.contextFiles = files
	return &out
}

// MergeOrder returns the files of root's pipeline in the order GitLab merges
// them: each file after the files it includes, so the root comes last. A file
// included more than once counts where it is included last, since that time
// overrides the earlier ones. Walking the includes backwards and keeping the
// first visit finds that place, and stops at a cycle.
func MergeOrder(root *Document) []*Document {
	var order []*Document
	seen := map[*Document]bool{}
	var walk func(d *Document)
	walk = func(d *Document) {
		if seen[d] {
			return
		}
		seen[d] = true
		order = append(order, d)
		for _, included := range slices.Backward(d.Includes) {
			walk(included)
		}
	}
	walk(root)
	slices.Reverse(order)
	return order
}

// contextMerge is one WithContext call. own says whether the file being merged
// is the document itself, whose nodes stay as they are.
type contextMerge struct {
	own     bool
	foreign bool
	copies  map[*yaml.Node]*yaml.Node
	// base and last are the current file's offset and its highest line so far.
	base, last int
	// merged remembers pairs: expanded aliases share nodes, and merging them
	// again wherever they appear would grow exponentially with their nesting.
	merged map[[2]*yaml.Node]*yaml.Node
}

func (m *contextMerge) node(n *yaml.Node) *yaml.Node {
	if m.own {
		return n
	}
	m.foreign = true
	return m.copy(n)
}

// line returns where a node of the current file goes. Past the room below
// ContextLine/2, which takes half a million lines of pipeline, the origin is
// given up.
func (m *contextMerge) line(n *yaml.Node) int {
	end := n.Line + strings.Count(n.Value, "\n") + 1
	if n.Line <= 0 || m.base+end >= -ContextLine/2 {
		return ContextLine
	}
	m.last = max(m.last, end)
	return ContextLine + m.base + n.Line
}

// over returns the merge of high, from the file being merged, over low, the
// result so far.
func (m *contextMerge) over(low, high *yaml.Node) *yaml.Node {
	if low.Kind != yaml.MappingNode || high.Kind != yaml.MappingNode {
		return m.node(high)
	}
	pair := [2]*yaml.Node{low, high}
	if done, ok := m.merged[pair]; ok {
		return done
	}
	out := *high
	if !m.own {
		m.foreign = true
		out.Line, out.Column = m.line(high), 0
	}
	m.merged[pair] = &out
	out.Content = append([]*yaml.Node{}, low.Content...)
	at := make(map[string]int, len(low.Content)/2)
	for i := 0; i+1 < len(low.Content); i += 2 {
		at[low.Content[i].Value] = i
	}
	for i := 0; i+1 < len(high.Content); i += 2 {
		key, value := high.Content[i], high.Content[i+1]
		if j, ok := at[key.Value]; ok {
			out.Content[j], out.Content[j+1] = m.node(key), m.over(low.Content[j+1], value)
			continue
		}
		out.Content = append(out.Content, m.node(key), m.node(value))
	}
	return &out
}

func contextKey(name string) bool {
	return strings.HasPrefix(name, ".") || (reservedKeys[name] && name != "include")
}

// copy copies n onto its context line. Unlike deepCopyNode it leaves the
// traced source lines behind, since they belong to the other file, and it
// copies a node shared by expanded aliases once, so the copy stays as small
// as the original.
func (m *contextMerge) copy(n *yaml.Node) *yaml.Node {
	if cp, ok := m.copies[n]; ok {
		return cp
	}
	cp := *n
	cp.Line, cp.Column = m.line(n), 0
	m.copies[n] = &cp
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, c := range n.Content {
			cp.Content[i] = m.copy(c)
		}
	}
	return &cp
}
