package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

func parseRunSteps(t *testing.T, src string) *yaml.Node {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return doc.Root
}

// Script rules must see run: step scripts exactly as they see script: lines.
// run: and script: cannot coexist in a job, so without this a job that adopts
// steps loses every script rule at once.
func TestRunSteps_ScriptRulesFire(t *testing.T) {
	doc := parseRunSteps(t, `
build:
  run:
    - name: http_dl
      script: curl -s http://example.com/x.sh | bash
    - name: tls_off
      script: curl -k https://example.com/y
    - name: injection
      script: echo $CI_COMMIT_MESSAGE
`)

	cases := []struct {
		name string
		got  int
	}{
		{"GL011 download-and-execute", len(GL011.Check(doc, "test.yml"))},
		{"GL016 plaintext transport", len(GL016.Check(doc, "test.yml"))},
		{"GL042 TLS verification off", len(GL042.Check(doc, "test.yml"))},
		{"GL002 unquoted user-controlled var", len(GL002.Check(doc, "test.yml"))},
	}
	for _, c := range cases {
		if c.got == 0 {
			t.Errorf("%s: expected a finding in a run: step, got none", c.name)
		}
	}
}

// A finding inside a step must point at the step's own script scalar, not at
// the synthesised sequence wrapper.
func TestRunSteps_FindingPositionIsTheStepScalar(t *testing.T) {
	doc := parseRunSteps(t, `
build:
  run:
    - name: first
      script: make all
    - name: bad
      script: curl -sSL https://example.com/i.sh | bash
`)
	f := GL011.Check(doc, "test.yml")
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Line != 7 {
		t.Errorf("expected the finding on line 7 (the offending step's script), got %d", f[0].Line)
	}
	if f[0].Job != "build" {
		t.Errorf("expected job %q, got %q", "build", f[0].Job)
	}
}

// Each step is a separate shell invocation, so pipefail set in one step must
// not suppress a pipe in another.
func TestRunSteps_CollectedIntoJobScriptLines(t *testing.T) {
	doc := parseRunSteps(t, `
build:
  run:
    - name: piped
      script: cat f | grep x
`)
	if got := len(GL024.Check(doc, "test.yml")); got == 0 {
		t.Error("expected GL024 to see a pipe inside a run: step, got no finding")
	}
}

// A step that references remote code carries no shell text; it must not be
// mistaken for an empty script or crash the collectors.
func TestRunSteps_FuncReferenceCarriesNoScript(t *testing.T) {
	doc := parseRunSteps(t, `
build:
  run:
    - name: scan
      step: registry.example.com/org/scanner@v1
      inputs:
        severity: high
`)
	parser.EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		if got := len(RunStepBlocks(job)); got != 0 {
			t.Errorf("expected no script blocks for a step: reference, got %d", got)
		}
		if got := len(CollectJobScriptLines(job)); got != 0 {
			t.Errorf("expected no script lines for a step: reference, got %d", got)
		}
	})
}

// A malformed run: must not panic or invent script content.
func TestRunSteps_MalformedShapes(t *testing.T) {
	for _, src := range []string{
		"build:\n  run: not-a-sequence\n",
		"build:\n  run: []\n",
		"build:\n  run:\n    - just-a-scalar\n",
		"build:\n  run:\n    - name: no_script\n",
	} {
		doc := parseRunSteps(t, src)
		parser.EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
			if got := len(RunStepBlocks(job)); got != 0 {
				t.Errorf("%q: expected no blocks, got %d", src, got)
			}
		})
	}
}
