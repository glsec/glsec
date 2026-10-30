// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
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

func TestGL025_SanitisedOnEarlierLine_NoFinding(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - |
      BRANCH=$(printf '%s' "$CI_COMMIT_REF_NAME" | tr -cd '[:alnum:]-_.')
      curl "https://hooks.example.com/notify?branch=${BRANCH}"
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for a sanitised value, got %d", len(f))
	}
}

func TestGL025_UnsanitisedAssignment(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - |
      B=$CI_COMMIT_REF_NAME
      C="x-$B"
      curl "https://hooks.example.com/notify?branch=$C"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding through the assignments, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "CI_COMMIT_REF_NAME") {
		t.Errorf("message should name the source variable: %s", f[0].Message)
	}
}

func TestGL025_DataURLEncode_NoFinding(t *testing.T) {
	for _, src := range []string{`
notify:
  script:
    - curl -X POST https://hooks.example.com/notify \
        --data-urlencode "branch=$CI_COMMIT_REF_NAME"
`, `
notify:
  script:
    - |
      curl -X POST https://hooks.example.com/notify \
        --data-urlencode "branch=$CI_COMMIT_REF_NAME"
`} {
		if f := findings025(t, src); len(f) != 0 {
			t.Errorf("expected no finding for --data-urlencode, got %d", len(f))
		}
	}
}

func TestGL025_DataURLEncodeAndRawValue(t *testing.T) {
	f := findings025(t, `
notify:
  script:
    - curl -G https://hooks.example.com --data-urlencode "b=$CI_COMMIT_REF_NAME" -d "t=$CI_COMMIT_TITLE"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for the raw value next to the encoded one, got %d", len(f))
	}
}

// A request inside a double-quoted command substitution counts like an
// unquoted one (#1002).
func TestGL025_QuotedSubstitution(t *testing.T) {
	for line, want := range map[string]int{
		`ID="$(curl -fsS "https://api.example.com/releases/${CI_COMMIT_TAG}")"`:     1,
		`OTHER=$(curl -fsS "https://api.example.com/releases/${CI_COMMIT_TAG}")`:    1,
		`echo "id: $(curl -fsS https://api.example.com/x?ref=$CI_COMMIT_REF_NAME)"`: 1,
		`ID="$(curl -fsS https://api.example.com/releases/latest)"`:                 0,
		`echo '$(curl https://api.example.com/$CI_COMMIT_TAG)'`:                     0,
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - "+strconv.Quote(line)+"\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL025.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("%s: got %d findings, want %d", line, got, want)
		}
	}
}
