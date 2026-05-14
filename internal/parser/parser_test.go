package parser

import (
	"testing"

	"gopkg.in/yaml.v3"
)

var sampleCI = []byte(`
stages:
  - build
  - test

variables:
  GLOBAL: value

include:
  - project: company/templates
    file: /jobs/deploy.yml
    ref: main

build-job:
  stage: build
  image: node:latest
  script:
    - npm run build

test-job:
  stage: test
  script:
    - npm test
`)

func TestParse(t *testing.T) {
	doc, err := Parse(sampleCI, "test.yml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.Root.Kind != yaml.DocumentNode {
		t.Fatalf("expected DocumentNode, got %v", doc.Root.Kind)
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := Parse([]byte(""), "empty.yml")
	if err == nil {
		t.Fatal("expected error for empty document")
	}
}

func TestFindKey(t *testing.T) {
	doc, _ := Parse(sampleCI, "test.yml")
	mapping := doc.MappingNode()

	node := FindKey(mapping, "variables")
	if node == nil {
		t.Fatal("expected to find 'variables' key")
	}
	if node.Kind != yaml.MappingNode {
		t.Fatalf("expected MappingNode for variables, got %v", node.Kind)
	}

	missing := FindKey(mapping, "nonexistent")
	if missing != nil {
		t.Fatal("expected nil for missing key")
	}
}

func TestFindKeyNode_LineNumbers(t *testing.T) {
	doc, _ := Parse(sampleCI, "test.yml")
	mapping := doc.MappingNode()

	keyNode, valueNode := FindKeyNode(mapping, "variables")
	if keyNode == nil || valueNode == nil {
		t.Fatal("expected both key and value nodes")
	}
	if keyNode.Line == 0 {
		t.Fatal("expected non-zero line number for key node")
	}
	if valueNode.Line == 0 {
		t.Fatal("expected non-zero line number for value node")
	}
}

func TestEachJob(t *testing.T) {
	doc, _ := Parse(sampleCI, "test.yml")

	var jobs []string
	EachJob(doc.Root, func(name *yaml.Node, _ *yaml.Node) {
		jobs = append(jobs, name.Value)
	})

	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d: %v", len(jobs), jobs)
	}
	if jobs[0] != "build-job" || jobs[1] != "test-job" {
		t.Fatalf("unexpected job names: %v", jobs)
	}
}

func TestEachJob_SkipsReservedKeys(t *testing.T) {
	doc, _ := Parse(sampleCI, "test.yml")

	EachJob(doc.Root, func(name *yaml.Node, _ *yaml.Node) {
		if reservedKeys[name.Value] {
			t.Errorf("EachJob yielded reserved key: %s", name.Value)
		}
	})
}

func TestEachJob_LineNumbers(t *testing.T) {
	doc, _ := Parse(sampleCI, "test.yml")

	EachJob(doc.Root, func(name *yaml.Node, _ *yaml.Node) {
		if name.Line == 0 {
			t.Errorf("job %q has zero line number", name.Value)
		}
	})
}
