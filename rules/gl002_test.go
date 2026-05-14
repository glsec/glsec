package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings002(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL002.Check(doc.Root, "test.yml")
}

func TestGL002_UnquotedRefName(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - ./run.sh $CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL002_QuotedRefName(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo "$CI_COMMIT_REF_NAME"
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for double-quoted variable, got %d", len(f))
	}
}

func TestGL002_BraceForm(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo ${CI_COMMIT_REF_NAME}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace form, got %d", len(f))
	}
}

func TestGL002_MultipleVars(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo $CI_COMMIT_TITLE
    - ./deploy.sh $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL002_SafeVariable(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo $CI_JOB_ID
    - echo $CI_PROJECT_NAME
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for non-user-controlled variables, got %d", len(f))
	}
}

func TestGL002_BeforeScript(t *testing.T) {
	f := findings002(t, `
build:
  before_script:
    - git checkout $CI_COMMIT_REF_NAME
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL002_TopLevelBeforeScript(t *testing.T) {
	f := findings002(t, `
before_script:
  - echo $CI_COMMIT_MESSAGE

build:
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in top-level before_script, got %d", len(f))
	}
}

func TestGL002_LineNumbers(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - ./run.sh $CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL002_SubshellInjection(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - make test BRANCH=$CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for assignment context, got %d", len(f))
	}
}
