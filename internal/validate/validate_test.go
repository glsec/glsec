// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"strings"
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
	if valErr == nil || !strings.Contains(valErr.Error(), "expected a top-level mapping") {
		t.Errorf("err = %v, want the top-level mapping error", valErr)
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

func TestFile_FragmentsAreRecognised(t *testing.T) {
	for name, src := range map[string]string{
		"hidden rules":   ".rules:\n  rules:\n    - if: $CI_COMMIT_TAG\n",
		"anchor only":    ".if-mr: &if-mr\n  if: $CI_MERGE_REQUEST_ID\n",
		"hidden scripts": ".scripts:\n  setup:\n    - echo hi\n",
		"hidden scalar":  ".version: &version \"1\"\n",
		"extends":        "job:\n  extends: .base\n",
		"merge key":      ".a: &a {stage: test}\njob:\n  <<: *a\n",
		"needs":          "deploy:\n  needs: [build]\n",
		"rules":          "job:\n  rules:\n    - when: never\n",
		"stage":          "job:\n  stage: test\n",
		"tags":           "job:\n  tags: [docker]\n",
		"variables":      "job:\n  variables:\n    A: b\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := File("test.yml", parse(t, src)); err != nil {
				t.Errorf("fragment should be recognised: %v", err)
			}
		})
	}
}

func TestFile_OtherYAMLFormatsAreRejected(t *testing.T) {
	for name, src := range map[string]string{
		"compose v1":     "web:\n  image: nginx\n  ports: [\"80:80\"]\n  environment:\n    A: b\n",
		"kubernetes":     "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\nspec:\n  containers: []\n",
		"actions":        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n",
		"misspelt job":   "build:\n  scirpt:\n    - make\n", //nolint:misspell // the typo is the test case
		"misspelt stage": "build:\n  stgae: test\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := File("test.yml", parse(t, src)); err == nil {
				t.Error("expected an error for a file that is not GitLab CI")
			}
		})
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
