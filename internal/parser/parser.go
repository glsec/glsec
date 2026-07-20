package parser

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type Document struct {
	Root *yaml.Node
	File string
	// ComponentTemplate reports whether the file is a GitLab CI/CD component
	// template (a `spec:` document, then the template body). Root then points at
	// the body. Such a file is a fragment, so rules that reason about a whole
	// pipeline do not apply to it.
	ComponentTemplate bool
}

func ParseFile(path string) (*Document, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: intentional, reads user-supplied files
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data, path)
}

func Parse(data []byte, file string) (*Document, error) {
	// Decode every document, not just the first: a CI/CD component template is a
	// two-document stream (`spec:` inputs, then the template body).
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		if n.Kind != 0 {
			docs = append(docs, &n)
		}
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("%s: empty document", file)
	}

	root := docs[0]
	component := false
	if len(docs) > 1 && hasSpecHeader(docs[0]) {
		root = docs[1]
		component = true
	}
	ResolveReferences(root)
	return &Document{Root: root, File: file, ComponentTemplate: component}, nil
}

// hasSpecHeader reports whether a document is a component template's `spec:`
// header. Only the key matters; its contents are input declarations, not CI
// configuration, so there is nothing in them for the rules to check.
func hasSpecHeader(doc *yaml.Node) bool {
	mapping := Unwrap(doc)
	if mapping.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "spec" {
			return true
		}
	}
	return false
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
