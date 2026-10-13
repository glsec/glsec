package parser

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Document struct {
	Root *yaml.Node
	File string
	// Spec is the `spec:` header of a two-document file (input declarations,
	// then the body), or nil. Root then points at the body.
	Spec *yaml.Node
	// ComponentTemplate reports whether the file is a GitLab CI/CD component
	// template or an included file with a `spec:` header. Such a file is a
	// fragment, so rules that reason about a whole pipeline do not apply to it.
	// A root .gitlab-ci.yml with a `spec:` header declares pipeline inputs and
	// is still a whole pipeline.
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

	doc := &Document{Root: docs[0], File: file}
	if len(docs) > 1 && hasSpecHeader(docs[0]) {
		doc.Spec = docs[0]
		doc.Root = docs[1]
		doc.ComponentTemplate = !isRootPipelineFile(file)
	}
	ExpandAliases(doc.Root)
	ExpandAliases(doc.Spec)
	ResolveReferences(doc.Root)
	return doc, nil
}

// isRootPipelineFile reports whether file is named like a project's root CI
// configuration, the only place GitLab accepts pipeline-level `spec:inputs`.
func isRootPipelineFile(file string) bool {
	base := filepath.Base(file)
	return base == ".gitlab-ci.yml" || base == ".gitlab-ci.yaml"
}

// hasSpecHeader reports whether a document is a `spec:` header. Only the key
// matters; its contents are input declarations, not CI configuration.
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

// RunStepScripts returns the inline script scalar of each step in a job's run:
// sequence. run: is the CI/CD Steps alternative to script: and is mutually
// exclusive with it, so without this a job that uses it has no script content
// at all from the scanner's point of view. A step carries either an inline
// script string or a step:/func: reference to remote code; only the former
// holds shell text to scan.
func RunStepScripts(job *yaml.Node) []*yaml.Node {
	run := FindKey(job, "run")
	if run == nil || run.Kind != yaml.SequenceNode {
		return nil
	}
	var scripts []*yaml.Node
	for _, step := range run.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		if script := FindKey(step, "script"); script != nil && script.Kind == yaml.ScalarNode {
			scripts = append(scripts, script)
		}
	}
	return scripts
}

// RunStepBlocks wraps each script from RunStepScripts in a single-item sequence
// node, so callers that process script *sequences* need no special case for the
// scalar shape a step uses. Each step is a separate shell invocation, so each
// gets its own block rather than being pooled. Findings report the wrapped
// scalar's own position, never the wrapper's.
func RunStepBlocks(job *yaml.Node) []*yaml.Node {
	scripts := RunStepScripts(job)
	blocks := make([]*yaml.Node, 0, len(scripts))
	for _, script := range scripts {
		blocks = append(blocks, &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{script}})
	}
	return blocks
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
