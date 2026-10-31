// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings003(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL003.Check(doc.Root, "test.yml")
}

func TestGL003_LocalInclude(t *testing.T) {
	f := findings003(t, `
include:
  - local: '/templates/security.yml'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for local include, got %d", len(f))
	}
}

func TestGL003_TemplateInclude(t *testing.T) {
	f := findings003(t, `
include:
  - template: 'Security/SAST.gitlab-ci.yml'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for template include, got %d", len(f))
	}
}

func TestGL003_ScalarShorthand(t *testing.T) {
	f := findings003(t, `
include: '/templates/security.yml'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for scalar shorthand include, got %d", len(f))
	}
}

func TestGL003_RemoteInclude(t *testing.T) {
	f := findings003(t, `
include:
  - remote: 'https://example.com/templates/security.yml'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for remote include, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL003_RemoteIncludeWithIntegrity_NoFinding(t *testing.T) {
	f := findings003(t, `
include:
  - remote: 'https://example.com/templates/security.yml'
    integrity: 'sha256-L3/GAoKaw0Arw6hDCKeKQlV1QPEgHYxGBHsH4zG1IY8='
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for a remote include pinned with integrity:, got %d", len(f))
	}
}

func TestGL003_RemoteIncludeWithInvalidIntegrity(t *testing.T) {
	for _, integrity := range []string{"$TEMPLATE_HASH", "sha256-short=", "sha512-L3/GAoKaw0Arw6hDCKeKQlV1QPEgHYxGBHsH4zG1IY8=", "''"} {
		f := findings003(t, `
include:
  - remote: 'https://example.com/templates/security.yml'
    integrity: `+integrity+`
`)
		if len(f) != 1 {
			t.Errorf("integrity %s: expected 1 finding, got %d", integrity, len(f))
		}
	}
}

func TestGL003_ProjectMissingRef(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing ref, got %d", len(f))
	}
}

func TestGL003_ProjectMutableRef(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
    ref: main
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mutable ref, got %d", len(f))
	}
}

func TestGL003_ProjectPinnedTag(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
    ref: v1.2.3
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for pinned tag, got %d", len(f))
	}
}

func TestGL003_ProjectPinnedSHA(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
    ref: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for SHA-pinned ref, got %d", len(f))
	}
}

func TestGL003_ComponentMutableRef(t *testing.T) {
	f := findings003(t, `
include:
  - component: 'gitlab.com/my-org/my-component/build@main'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for component with mutable ref, got %d", len(f))
	}
}

func TestGL003_ComponentPinnedVersion(t *testing.T) {
	f := findings003(t, `
include:
  - component: 'gitlab.com/my-org/my-component/build@1.0.0'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for versioned component, got %d", len(f))
	}
}

func TestGL003_ComponentMissingRef(t *testing.T) {
	f := findings003(t, `
include:
  - component: 'gitlab.com/my-org/my-component/build'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for component missing version, got %d", len(f))
	}
}

func TestGL003_Mixed(t *testing.T) {
	f := findings003(t, `
include:
  - local: '/safe.yml'
  - project: 'company/templates'
    file: '/deploy.yml'
    ref: main
  - remote: 'https://example.com/template.yml'
  - template: 'SAST.gitlab-ci.yml'
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (mutable ref + remote), got %d", len(f))
	}
}

func TestGL003_ProjectStableRef(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
    ref: stable
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for stable ref, got %d", len(f))
	}
}

func TestGL003_ProjectTrunkRef(t *testing.T) {
	f := findings003(t, `
include:
  - project: 'company/ci-templates'
    file: '/jobs/deploy.yml'
    ref: trunk
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for trunk ref, got %d", len(f))
	}
}

func TestGL003_ComponentTildeLatest(t *testing.T) {
	f := findings003(t, `
include:
  - component: 'gitlab.com/my-org/my-component/build@~latest'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ~latest component ref, got %d", len(f))
	}
}

func TestGL003_LineNumbers(t *testing.T) {
	f := findings003(t, `
include:
  - remote: 'https://example.com/template.yml'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestCommitPinnedRawURL(t *testing.T) {
	const sha = "3f2a9c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a39"
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://raw.githubusercontent.com/org/templates/" + sha + "/ci/lint.yml", true},
		{"https://github.com/org/templates/raw/" + sha + "/ci/lint.yml", true},
		{"https://gitlab.example.com/group/sub/project/-/raw/" + sha + "/ci/lint.yml", true},
		{"https://bitbucket.org/org/templates/raw/" + sha + "/lint.yml", true},
		{"https://codeberg.org/org/templates/raw/commit/" + sha + "/lint.yml", true},
		{"https://gitlab.com/api/v4/projects/123/repository/files/ci%2Flint.yml/raw?ref=" + sha, true},
		{"https://raw.githubusercontent.com/org/templates/main/ci/lint.yml", false},
		{"https://raw.githubusercontent.com/org/templates/v1.2.3/ci/lint.yml", false},
		{"https://raw.githubusercontent.com/org/templates/" + sha[:12] + "/ci/lint.yml", false},
		{"https://raw.githubusercontent.com/org/" + sha + "/main/lint.yml", false},
		{"https://gitlab.com/group/project/-/raw/main/lint.yml", false},
		{"https://gitlab.com/group/project/-/raw/" + sha, false},
		{"https://codeberg.org/org/templates/raw/branch/main/lint.yml", false},
		{"https://gitlab.com/api/v4/projects/123/repository/files/lint.yml/raw?ref=main", false},
		{"https://example.com/raw/" + sha + "/lint.yml", false},
		{"https://example.com/" + sha + ".yml", false},
		{"ftp://example.com/x/y/raw/" + sha + "/lint.yml", false},
		{"https://exa mple.com/%zz", false},
	} {
		if got := commitPinnedRawURL(tc.url); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.url, got, tc.want)
		}
	}
}
