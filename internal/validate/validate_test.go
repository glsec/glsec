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
