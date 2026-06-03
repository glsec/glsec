package parser

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Document struct {
	Root *yaml.Node
	File string
}

func ParseFile(path string) (*Document, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: intentional, reads user-supplied files
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data, path)
}

func Parse(data []byte, file string) (*Document, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	if root.Kind == 0 {
		return nil, fmt.Errorf("%s: empty document", file)
	}
	ResolveReferences(&root)
	return &Document{Root: &root, File: file}, nil
}

// MappingNode returns the top-level mapping node of the document.
func (d *Document) MappingNode() *yaml.Node {
	if d.Root.Kind == yaml.DocumentNode && len(d.Root.Content) > 0 {
		return d.Root.Content[0]
	}
	return d.Root
}

// FindKey returns the value node for a key in a MappingNode, or nil if not found.
func FindKey(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// FindKeyNode returns both the key and value nodes for a given key.
func FindKeyNode(node *yaml.Node, key string) (keyNode, valueNode *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i], node.Content[i+1]
		}
	}
	return nil, nil
}

// Unwrap returns the first content node of a DocumentNode, or the node itself.
func Unwrap(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return node.Content[0]
	}
	return node
}

// ScalarContentLine returns the source line of the i-th line of a scalar
// node's value. For block scalars (literal "|" or folded ">"), node.Line points
// at the indicator line and the content begins on the next line, so the offset
// is shifted by one; for plain or quoted scalars node.Line is the content line
// itself. Use this when reporting findings located within a multi-line scalar.
func ScalarContentLine(node *yaml.Node, i int) int {
	if node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return node.Line + 1 + i
	}
	return node.Line + i
}

// reservedKeys are top-level GitLab CI keys that are configuration, not job definitions.
var reservedKeys = map[string]bool{
	"stages":        true,
	"variables":     true,
	"default":       true,
	"workflow":      true,
	"include":       true,
	"image":         true,
	"services":      true,
	"cache":         true,
	"before_script": true,
	"after_script":  true,
}

// CountJobs returns the number of job definitions in the document.
func CountJobs(doc *yaml.Node) int {
	n := 0
	EachJob(doc, func(*yaml.Node, *yaml.Node) { n++ })
	return n
}

// EachJob calls fn for each job definition in the document.
func EachJob(doc *yaml.Node, fn func(name *yaml.Node, job *yaml.Node)) {
	mapping := doc
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		mapping = doc.Content[0]
	}
	if mapping.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key := mapping.Content[i]
		val := mapping.Content[i+1]
		if reservedKeys[key.Value] || val.Kind != yaml.MappingNode {
			continue
		}
		fn(key, val)
	}
}
