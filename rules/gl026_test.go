// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings026(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL026.Check(doc.Root, "test.yml")
}

const sha40 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func TestGL026_CloneWithMutableBranch(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone --branch main https://github.com/org/tools.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL026_CloneWithMutableTag(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone --depth 1 --branch v2.3 https://github.com/org/lib.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mutable tag, got %d", len(f))
	}
}

func TestGL026_CloneBranchEqualsForm(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone --branch=main https://github.com/org/tools.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --branch=main, got %d", len(f))
	}
	if f[0].Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestGL026_CloneBranchEqualsWithSHA_NoFinding(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone --branch=`+sha40+` https://github.com/org/lib.git
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for --branch=<sha>, got %d", len(f))
	}
}

func TestGL026_CloneWithBranchFlagShortForm(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone -b develop https://github.com/org/lib.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for -b develop, got %d", len(f))
	}
}

func TestGL026_CloneBareNoSHACheckout(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone https://github.com/org/shared-scripts.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for bare clone without SHA checkout, got %d", len(f))
	}
}

func TestGL026_CloneBareWithSHACheckout_NoFinding(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone https://github.com/org/shared-scripts.git
    - git -C shared-scripts checkout `+sha40+`
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for bare clone paired with SHA checkout, got %d", len(f))
	}
}

func TestGL026_CloneWithSHABranch_NoFinding(t *testing.T) {
	// --branch accepts tag names but not SHAs in practice; if someone passes
	// a SHA-shaped string we treat it as safe.
	f := findings026(t, `
build:
  script:
    - git clone --branch `+sha40+` https://github.com/org/lib.git
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when --branch value is a SHA, got %d", len(f))
	}
}

func TestGL026_CheckoutMutableBranch(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git checkout main
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for checkout of mutable branch, got %d", len(f))
	}
}

func TestGL026_CheckoutSHA_NoFinding(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git checkout `+sha40+`
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for SHA-pinned checkout, got %d", len(f))
	}
}

func TestGL026_CheckoutCreateBranch_NoFinding(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git checkout -b new-feature
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for branch creation with -b, got %d", len(f))
	}
}

func TestGL026_GitCWithSHACheckout_NoFinding(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone https://github.com/org/tools.git
    - git -C tools checkout `+sha40+`
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for git -C checkout with SHA, got %d", len(f))
	}
}

func TestGL026_NoBranchFlagWithMutableBranchClone(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone --branch main https://github.com/org/tools.git
    - git clone https://github.com/org/other.git
    - git -C other checkout `+sha40+`
`)
	// Only the --branch main clone should be flagged; bare clone has SHA checkout.
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL026_NoGitCommands_NoFinding(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - go build ./...
    - go test ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-git script, got %d", len(f))
	}
}

func TestGL026_LineNumber(t *testing.T) {
	f := findings026(t, `
build:
  script:
    - git clone --branch main https://github.com/org/tools.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

// Checking out the project's own branch, or cloning the local repository,
// brings in no third-party code (#984).
func TestGL026_OwnRepository(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{`git fetch origin && git checkout $CI_DEFAULT_BRANCH`, 0},
		{`git checkout "${CI_COMMIT_REF_NAME}"`, 0},
		{`git checkout origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME`, 0},
		{`git clone -b 1.0 . copy`, 0},
		{`git clone --branch main "$CI_PROJECT_DIR" /tmp/copy`, 0},
		{`git clone --depth 1 --branch "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" "$CI_REPOSITORY_URL" /tmp/base`, 0},
		{`git -C vendor/lib checkout $CI_DEFAULT_BRANCH`, 1},
		{`git checkout develop`, 1},
		{`git clone --branch main https://github.com/org/tools.git`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - '"+tc.line+"'\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL026.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.line, got, tc.want)
		}
	}
	// A quoted ref is named once quoted in the message.
	doc, err := parser.Parse([]byte("job:\n  script:\n    - 'git clone --branch \"$BRANCH\" https://example.com/lib.git'\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	if f := GL026.Check(doc.Root, "test.yml"); len(f) != 1 || !strings.Contains(f[0].Message, `ref "$BRANCH"`) {
		t.Errorf("got %v, want the ref quoted once", f)
	}
}

func TestLocalCloneSource_NoSource(t *testing.T) {
	if localCloneSource([]string{"git", "clone", "--depth", "1"}) {
		t.Error("a clone without a source isn't a local clone")
	}
}
