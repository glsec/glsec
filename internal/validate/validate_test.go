// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func parse(t *testing.T, src string) *parser.Document {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return doc
}

func TestFile_ValidGitLabCI(t *testing.T) {
	doc := parse(t, `
stages: [build]
build:
  script: [make]
`)
	warns, err := File("test.yml", doc)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
}

func TestFile_ExtensionWarning(t *testing.T) {
	doc := parse(t, `
stages: [build]
build:
  script: [make]
`)
	warns, err := File("pipeline", doc)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(warns) == 0 {
		t.Error("expected extension warning")
	}
}

func TestFile_YamlExtension(t *testing.T) {
	doc := parse(t, `stages: [build]`)
	warns, err := File("ci.yaml", doc)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("unexpected warnings for .yaml extension: %v", warns)
	}
}

func TestFile_NotAMapping(t *testing.T) {
	// A YAML list at the top level is not a valid GitLab CI file.
	doc, err := parser.Parse([]byte("- item1\n- item2\n"), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	_, valErr := File("test.yml", doc)
	if valErr == nil {
		t.Error("expected error for non-mapping top-level")
	}
}

func TestFile_NoGitLabContent(t *testing.T) {
	doc := parse(t, `
foo: bar
baz: qux
`)
	_, err := File("test.yml", doc)
	if err == nil {
		t.Error("expected error for file with no GitLab CI content")
	}
}

func TestFile_KnownKeyIsEnough(t *testing.T) {
	for _, key := range []string{"stages", "variables", "include", "default", "workflow"} {
		doc := parse(t, key+": []\n")
		_, err := File("test.yml", doc)
		if err != nil {
			t.Errorf("key %q should be recognised as GitLab CI content: %v", key, err)
		}
	}
}

func TestFile_JobWithScriptIsEnough(t *testing.T) {
	doc := parse(t, `
my-job:
  script:
    - echo hello
`)
	_, err := File("test.yml", doc)
	if err != nil {
		t.Errorf("job with script should be recognised: %v", err)
	}
}

func TestFile_RunStepsOnly(t *testing.T) {
	// run: is the CI/CD Steps alternative to script: and is mutually exclusive
	// with it, so a steps-only pipeline has no script: key to recognise.
	doc := parse(t, `
build:
  run:
    - name: compile
      script: make all
`)
	warns, err := File("test.yml", doc)
	if err != nil {
		t.Errorf("unexpected error for a run:-only pipeline: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
}

func TestFile_RunStepsWithFuncReferenceOnly(t *testing.T) {
	// A step may reference remote code instead of carrying an inline script.
	// The file is still GitLab CI.
	doc := parse(t, `
build:
  run:
    - name: scan
      step: registry.example.com/org/scanner@v1
`)
	if _, err := File("test.yml", doc); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFile_TriggerJobsOnly(t *testing.T) {
	// A parent pipeline may consist of nothing but trigger jobs for its
	// children; trigger jobs have no script: or run:.
	doc := parse(t, `
child:
  trigger:
    include: ci/child.yml
downstream:
  trigger:
    project: group/other
`)
	if _, err := File("test.yml", doc); err != nil {
		t.Errorf("unexpected error for a trigger-only pipeline: %v", err)
	}
}

func TestFile_IgnoredDocumentWarning(t *testing.T) {
	doc := parse(t, "spec:\n  inputs: {}\n---\njob:\n  script: [a]\n---\njob2:\n  script: [b]\n")
	warns, err := File("test.yml", doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "test.yml:4: document ignored: after a spec: header GitLab runs only the last document"
	if len(warns) != 1 || warns[0] != want {
		t.Errorf("warnings = %q, want [%q]", warns, want)
	}
}

func TestFile_KeywordJobWarning(t *testing.T) {
	doc := parse(t, "default:\n  script: [./deploy.sh]\nreal:\n  script: [x]\n")
	warns, err := File("test.yml", doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `test.yml:1: default: has job keywords, so GitLab runs it as a job named "default" and it sets no defaults; glsec scans it as that job`
	if len(warns) != 1 || warns[0] != want {
		t.Errorf("warnings = %q, want [%q]", warns, want)
	}
}
