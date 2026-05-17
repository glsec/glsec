package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings025(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL025.Check(doc.Root, "test.yml")
}

func TestGL025_CurlWithRefName(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl https://hooks.example.com/notify?branch=$CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL025_CurlWithRefSlug(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl https://hooks.example.com/notify?branch=$CI_COMMIT_REF_SLUG
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL025_CurlWithMRTitle(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl -d "msg=$CI_MERGE_REQUEST_TITLE" https://api.example.com/comment
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL025_WgetWithCommitMessage(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - wget "https://api.example.com/hook?msg=$CI_COMMIT_MESSAGE"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL025_CurlWithMRSourceBranch(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl https://api.example.com/pr/$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL025_CurlWithCommitTitle(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl -H "X-Title=$CI_COMMIT_TITLE" https://api.example.com/notify
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL025_CurlNoUserVar_NoFinding(t *testing.T) {
	f := findings025(t, `
deploy:
  script:
    - curl https://api.example.com/deploy
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for curl without user-controlled var, got %d", len(f))
	}
}

func TestGL025_CurlWithSafeVar_NoFinding(t *testing.T) {
	f := findings025(t, `
deploy:
  script:
    - curl -H "Authorization Bearer $MY_TOKEN" https://api.example.com/deploy
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for curl with non-user-controlled var, got %d", len(f))
	}
}

func TestGL025_NoCurlOrWget_NoFinding(t *testing.T) {
	f := findings025(t, `
build:
  script:
    - go build ./...
    - echo $CI_COMMIT_REF_NAME
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when no curl/wget, got %d", len(f))
	}
}

func TestGL025_MultipleLinesOneFinding(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl https://hooks.example.com/?ref=$CI_COMMIT_REF_NAME
    - wget https://api.example.com/?msg=$CI_COMMIT_MESSAGE
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (one per offending line), got %d", len(f))
	}
}

func TestGL025_LineNumber(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl https://hooks.example.com/?ref=$CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL025_BracedVar(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl https://hooks.example.com/?ref=${CI_COMMIT_REF_NAME}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for braced variable, got %d", len(f))
	}
}

func TestGL025_CommitBranch(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl https://api.example.com/builds/$CI_COMMIT_BRANCH
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_BRANCH, got %d", len(f))
	}
}

func TestGL025_CommitTag(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl https://api.example.com/releases/$CI_COMMIT_TAG
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_TAG, got %d", len(f))
	}
}
