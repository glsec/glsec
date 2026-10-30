// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	for _, file := range []string{".gitlab-ci.yml", "repo/.gitlab-ci.yaml", StdinName} {
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

// GitLab runs the last document after a spec: header and ignores the ones in
// between (#908).
func TestParse_SpecHeaderUsesLastDocument(t *testing.T) {
	src := "spec:\n  inputs: {}\n---\njob:\n  script: [a]\n---\njob2:\n  script: [b]\n"
	doc, err := Parse([]byte(src), ".gitlab-ci.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if FindKey(doc.MappingNode(), "job2") == nil || FindKey(doc.MappingNode(), "job") != nil {
		t.Error("expected the last document to be linted, not the first after the header")
	}
	if len(doc.IgnoredDocuments) != 1 || doc.IgnoredDocuments[0] != 4 {
		t.Errorf("IgnoredDocuments = %v, want [4]", doc.IgnoredDocuments)
	}
}

func TestParse_SpecHeaderAndOneDocumentIgnoresNothing(t *testing.T) {
	doc, err := Parse([]byte("spec:\n  inputs: {}\n---\njob:\n  script: [a]\n"), ".gitlab-ci.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if FindKey(doc.MappingNode(), "job") == nil {
		t.Error("expected the document after the header to be linted")
	}
	if len(doc.IgnoredDocuments) != 0 {
		t.Errorf("IgnoredDocuments = %v, want none", doc.IgnoredDocuments)
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

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitlab-ci.yml")
	if err := os.WriteFile(path, []byte("build:\n  script: [make]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.File != path || FindKey(doc.MappingNode(), "build") == nil {
		t.Errorf("unexpected document for %s: file %q", path, doc.File)
	}

	_, err = ParseFile(filepath.Join(dir, "missing.yml"))
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "missing.yml") {
		t.Errorf("got %v, want a not-exist error naming the file", err)
	}
}

func TestParse_SyntaxError(t *testing.T) {
	_, err := Parse([]byte("build:\n  script: [make\n"), "broken.yml")
	if err == nil || !strings.Contains(err.Error(), "parse broken.yml") {
		t.Errorf("got %v, want a parse error naming the file", err)
	}
}

func TestParse_TopLevelNotAMapping(t *testing.T) {
	for _, tc := range []struct {
		src  string
		kind yaml.Kind
	}{
		{"- build\n- test\n", yaml.SequenceNode},
		{"just a string\n", yaml.ScalarNode},
	} {
		doc, err := Parse([]byte(tc.src), "test.yml")
		if err != nil {
			t.Fatalf("%q: %v", tc.src, err)
		}
		top := doc.MappingNode()
		if top.Kind != tc.kind || Unwrap(doc.Root) != top {
			t.Errorf("%q: MappingNode/Unwrap returned kind %d, want %d", tc.src, top.Kind, tc.kind)
		}
		if FindKey(top, "build") != nil {
			t.Errorf("%q: FindKey on a non-mapping must return nil", tc.src)
		}
		if k, v := FindKeyNode(top, "build"); k != nil || v != nil {
			t.Errorf("%q: FindKeyNode on a non-mapping must return nil, nil", tc.src)
		}
		jobs := 0
		EachJob(doc.Root, func(*yaml.Node, *yaml.Node) { jobs++ })
		if jobs != 0 {
			t.Errorf("%q: EachJob visited %d jobs, want 0", tc.src, jobs)
		}
	}
}

func TestParse_ListBeforeSecondDocumentIsNoSpecHeader(t *testing.T) {
	doc, err := Parse([]byte("- a\n---\nbuild:\n  script: [make]\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Spec != nil || doc.MappingNode().Kind != yaml.SequenceNode {
		t.Errorf("a leading list is not a spec: header; got spec %v, root kind %d", doc.Spec, doc.MappingNode().Kind)
	}
}

func TestParse_EmptyDocumentInStream(t *testing.T) {
	// A trailing --- with nothing after it doesn't replace the pipeline.
	doc, err := Parse([]byte("build:\n  script: [make]\n---\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if FindKey(doc.MappingNode(), "build") == nil {
		t.Error("a trailing empty document must not become the root")
	}

	// A leading empty document is the first document, holding a null. It is not
	// skipped: the file then has no top-level mapping, which validate rejects,
	// so glsec reports an error instead of finding nothing.
	doc, err = Parse([]byte("---\n---\nbuild:\n  script: [make]\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if top := doc.MappingNode(); top.Kind != yaml.ScalarNode || top.Tag != "!!null" {
		t.Errorf("got kind %d tag %q, want the leading empty document's null", top.Kind, top.Tag)
	}
}

func TestMappingNode_RootWithoutDocument(t *testing.T) {
	m := &yaml.Node{Kind: yaml.MappingNode}
	if got := (&Document{Root: m}).MappingNode(); got != m {
		t.Errorf("a Root that is not a document node must be returned as is")
	}
	if Unwrap(m) != m {
		t.Errorf("Unwrap must return a non-document node as is")
	}
}

func TestFindKeyNode_Missing(t *testing.T) {
	doc, err := Parse([]byte("build:\n  script: [make]\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if k, v := FindKeyNode(doc.MappingNode(), "deploy"); k != nil || v != nil {
		t.Errorf("got %v, %v for a missing key, want nil, nil", k, v)
	}
}

func TestScalarContentLine(t *testing.T) {
	doc, err := Parse([]byte(`build:
  script:
    - "echo a"
    - |
      echo b
      echo c
    - >
      echo d

      echo e
    - echo f

      echo g
    - "echo h

      echo i"
    - "echo \"j\"

      echo k"
`), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	items := FindKey(FindKey(doc.MappingNode(), "build"), "script").Content
	for _, tc := range []struct {
		item, i, want int
		exact         bool
	}{
		{0, 0, 3, true},   // quoted: the content is on the node's own line
		{1, 0, 5, true},   // literal block: content starts one line after "|"
		{1, 1, 6, true},   // and keeps its lines one to one
		{2, 0, 8, true},   // folded block: content starts one line after ">"
		{2, 1, 10, true},  // its second value line, traced back to the source (#753)
		{3, 0, 11, true},  // plain scalar: its own line
		{3, 1, 13, true},  // "echo g", after the folded blank line
		{4, 1, 16, true},  // the same for a quoted scalar
		{5, 1, 17, false}, // an escape breaks the tracing: reported where the scalar starts
	} {
		value := strings.Split(items[tc.item].Value, "\n")
		if tc.i >= len(value) {
			t.Fatalf("item %d has %d value lines, test wants line %d", tc.item, len(value), tc.i)
		}
		if got := ScalarContentLine(items[tc.item], tc.i); got != tc.want {
			t.Errorf("item %d line %d (%q): got %d, want %d", tc.item, tc.i, value[tc.i], got, tc.want)
		}
		if got := ScalarLineExact(items[tc.item], tc.i); got != tc.exact {
			t.Errorf("item %d line %d: exact = %v, want %v", tc.item, tc.i, got, tc.exact)
		}
	}
}

func TestParseFileNamesAReadFailureOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipeline.yml")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("create a directory where the file should be: %v", err)
	}

	_, err := ParseFile(path)
	if err == nil {
		t.Fatal("expected an error reading a directory")
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("expected the os.PathError to survive, got %T: %v", err, err)
	}
	if got := strings.Count(err.Error(), path); got != 1 {
		t.Fatalf("path appears %d times in %q, want 1", got, err)
	}
}

// A default: or workflow: with job keywords is a job to GitLab, not defaults
// or workflow rules (#937).
func TestParse_KeywordJobs(t *testing.T) {
	src := "workflow:\n  stage: build\n  script: [./build.sh]\ndefault:\n  image: alpine:3.20.3\n  trigger:\n    include: child.yml\nreal:\n  script: [x]\n"
	doc, err := Parse([]byte(src), ".gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var jobs []string
	EachJob(doc.Root, func(name, _ *yaml.Node) { jobs = append(jobs, name.Value) })
	if strings.Join(jobs, ",") != "workflow,default,real" {
		t.Errorf("jobs = %v, want workflow, default and real", jobs)
	}
	if FindKey(doc.MappingNode(), "default") != nil || FindKey(doc.MappingNode(), "workflow") != nil {
		t.Error("FindKey must not return a default: or workflow: that is a job")
	}
	if k, v := FindKeyNode(doc.MappingNode(), "workflow"); k != nil || v != nil {
		t.Error("FindKeyNode must not return a workflow: that is a job")
	}
	if got := CountJobs(doc.Root); got != 3 {
		t.Errorf("CountJobs = %d, want 3", got)
	}
}

func TestParse_PlainDefaultAndWorkflowStayKeywords(t *testing.T) {
	doc, err := Parse([]byte("workflow:\n  rules:\n    - when: always\ndefault:\n  image: alpine:3.20.3\nreal:\n  script: [x]\n"), ".gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if FindKey(doc.MappingNode(), "default") == nil || FindKey(doc.MappingNode(), "workflow") == nil {
		t.Error("a default: and workflow: without job keywords are keywords")
	}
	if got := CountJobs(doc.Root); got != 1 {
		t.Errorf("CountJobs = %d, want 1", got)
	}
}
