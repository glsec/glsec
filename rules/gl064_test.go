package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings064(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL064.Check(doc.Root, "test.yml")
}

func TestGL064_TyposquatNamespace(t *testing.T) {
	f := findings064(t, `
include:
  - component: componets/opentofu/opentofu@1.0.0
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL064" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL064_ExactMatchNotFlagged(t *testing.T) {
	f := findings064(t, `
include:
  - component: components/opentofu/opentofu@1.0.0
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for exact match, got %d", len(f))
	}
}

func TestGL064_HostPrefixExactMatch(t *testing.T) {
	f := findings064(t, `
include:
  - component: gitlab.com/components/opentofu/opentofu@1.0.0
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for host-prefixed exact match, got %d", len(f))
	}
}

func TestGL064_MissingCharTyposquat(t *testing.T) {
	// Namespace dependabot-gitlb is one deletion from dependabot-gitlab.
	f := findings064(t, `
include:
  - component: dependabot-gitlb/dependabot-standalone/runner@2.0.0
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for dependabot-gitlb typo, got %d", len(f))
	}
}

func TestGL064_SameNamespaceNearMissNotFlagged(t *testing.T) {
	// One edit from components/opentofu but same namespace — owner controls it.
	f := findings064(t, `
include:
  - component: components/opentofux/opentofu@1.0.0
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for same-namespace near miss, got %d", len(f))
	}
}

func TestGL064_UnrelatedComponentNotFlagged(t *testing.T) {
	f := findings064(t, `
include:
  - component: my-org/my-project/build@1.0.0
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for unrelated component, got %d", len(f))
	}
}

func TestComponentResourcePath(t *testing.T) {
	cases := map[string]string{
		"componets/opentofu/opentofu@1.0.0":            "componets/opentofu",
		"gitlab.com/components/opentofu/opentofu@1.0.0": "components/opentofu",
		"a/b/c/d@1.0.0":                                "a/b/c",
		"foo/bar@1.0.0":                                "", // no component-name segment → too short
	}
	for in, want := range cases {
		if got := componentResourcePath(in); got != want {
			t.Errorf("componentResourcePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEditDistanceAtMostOne(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"abc", "abd", true},  // substitution
		{"abc", "ab", true},   // deletion
		{"abc", "abcd", true}, // insertion
		{"abc", "abc", false}, // identical (distance 0)
		{"abc", "axd", false}, // two substitutions
		{"abc", "abide", false},
		{"componets/opentofu", "components/opentofu", true},
	}
	for _, c := range cases {
		if got := editDistanceAtMostOne(c.a, c.b); got != c.want {
			t.Errorf("editDistanceAtMostOne(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCatalogCorpusLoaded(t *testing.T) {
	if len(catalogComponents) < 20 {
		t.Fatalf("expected a populated corpus, got %d entries", len(catalogComponents))
	}
}
