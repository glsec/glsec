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

func TestParse_ComponentTemplate(t *testing.T) {
	doc, err := Parse([]byte(`spec:
  inputs:
    version:
      default: "1.0.0"
---
scan-job:
  script: [echo hi]
`), "template.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !doc.ComponentTemplate {
		t.Error("expected the file to be detected as a component template")
	}
	m := doc.MappingNode()
	if FindKey(m, "scan-job") == nil {
		t.Error("expected the root to be the template body")
	}
	if FindKey(m, "spec") != nil {
		t.Error("the spec header must not be the linted document")
	}
	if doc.Spec == nil || FindKey(Unwrap(doc.Spec), "spec") == nil {
		t.Error("expected the spec header to be kept on the document")
	}
}

func TestParse_RootPipelineWithInputsIsNotComponentTemplate(t *testing.T) {
	src := []byte("spec:\n  inputs:\n    env:\n      default: dev\n---\nbuild:\n  script: [make]\n")
	for _, file := range []string{".gitlab-ci.yml", "repo/.gitlab-ci.yaml"} {
		doc, err := Parse(src, file)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if doc.ComponentTemplate {
			t.Errorf("%s: a root pipeline with spec:inputs must not be treated as a component template", file)
		}
		if doc.Spec == nil || FindKey(doc.MappingNode(), "build") == nil {
			t.Errorf("%s: expected the spec header kept and the body linted", file)
		}
	}
	doc, err := Parse(src, "ci/deploy.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !doc.ComponentTemplate {
		t.Error("an included file with a spec header is a fragment")
	}
}

func TestParse_PlainPipelineIsNotComponentTemplate(t *testing.T) {
	doc, err := Parse([]byte("build:\n  script: [make]\n"), "ci.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.ComponentTemplate {
		t.Error("a single-document pipeline must not be treated as a component template")
	}
}

func TestParse_MultiDocumentWithoutSpecUsesFirst(t *testing.T) {
	doc, err := Parse([]byte("build:\n  script: [make]\n---\nother:\n  script: [x]\n"), "ci.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.ComponentTemplate {
		t.Error("multiple documents without a spec header are not a component template")
	}
	if FindKey(doc.MappingNode(), "build") == nil {
		t.Error("expected the first document to be linted")
	}
}

func TestRunStepScripts(t *testing.T) {
	doc, err := Parse([]byte(`
build:
  run:
    - name: inline
      script: make all
    - name: remote
      step: registry.example.com/org/scanner@v1
    - name: second_inline
      script: make test
`), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	EachJob(doc.Root, func(_ *yaml.Node, job *yaml.Node) {
		scripts := RunStepScripts(job)
		if len(scripts) != 2 {
			t.Fatalf("expected 2 inline scripts (the step: reference carries none), got %d", len(scripts))
		}
		if scripts[0].Value != "make all" || scripts[1].Value != "make test" {
			t.Errorf("unexpected scripts: %q, %q", scripts[0].Value, scripts[1].Value)
		}
		blocks := RunStepBlocks(job)
		if len(blocks) != 2 {
			t.Fatalf("expected 2 blocks, got %d", len(blocks))
		}
		for i, b := range blocks {
			if b.Kind != yaml.SequenceNode || len(b.Content) != 1 {
				t.Errorf("block %d: expected a single-item sequence", i)
				continue
			}
			// The wrapped node must be the original scalar, so findings keep
			// their real position.
			if b.Content[0] != scripts[i] {
				t.Errorf("block %d: wrapper does not hold the original scalar node", i)
			}
		}
	})
}

func TestRunStepScripts_MalformedAndAbsent(t *testing.T) {
	for _, src := range []string{
		"build:\n  script: [make]\n",
		"build:\n  run: not-a-sequence\n",
		"build:\n  run: []\n",
		"build:\n  run:\n    - just-a-scalar\n",
		"build:\n  run:\n    - name: no_script\n",
		"build:\n  run:\n    - name: seq_script\n      script: [a, b]\n",
	} {
		doc, err := Parse([]byte(src), "test.yml")
		if err != nil {
			t.Fatalf("parse error for %q: %v", src, err)
		}
		EachJob(doc.Root, func(_ *yaml.Node, job *yaml.Node) {
			if got := len(RunStepScripts(job)); got != 0 {
				t.Errorf("%q: expected no scripts, got %d", src, got)
			}
		})
	}
}

func TestFindKeyMerged(t *testing.T) {
	doc, err := Parse([]byte(`.a: &a
  x: from-a
  y: from-a
.b: &b
  y: from-b
  z: from-b
job:
  <<: [*a, *b]
  x: own
ref: *a
`), "test.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m := doc.MappingNode()
	job := FindKey(m, "job")
	for key, want := range map[string]string{"x": "own", "y": "from-a", "z": "from-b"} {
		if got := FindKeyMerged(job, key); got == nil || got.Value != want {
			t.Errorf("%s: got %v, want %s", key, got, want)
		}
	}
	if FindKeyMerged(job, "missing") != nil {
		t.Error("expected nil for a missing key")
	}
	if got := FindKeyMerged(FindKey(m, "ref"), "x"); got == nil || got.Value != "from-a" {
		t.Error("expected FindKeyMerged to follow an alias")
	}
}
