package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings075(t *testing.T, yaml string, allowed []string) []finding.Finding {
	t.Helper()
	r := &gl075{allowedSources: allowed}
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return r.Check(doc.Root, "test.yml")
}

func TestGL075_NoOpWhenUnset(t *testing.T) {
	f := findings075(t, `
include:
  - project: other-group/evil
    ref: 1111111111111111111111111111111111111111
    file: /ci.yml
`, nil)
	if len(f) != 0 {
		t.Errorf("expected no findings when allowlist is empty, got %d", len(f))
	}
}

func TestGL075_ProjectDisallowed(t *testing.T) {
	f := findings075(t, `
include:
  - project: other-group/evil
    ref: 1111111111111111111111111111111111111111
    file: /ci.yml
`, []string{"my-group"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for untrusted project namespace, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "other-group/evil") {
		t.Errorf("expected project path in message, got %q", f[0].Message)
	}
}

func TestGL075_ProjectAllowedByNamespace(t *testing.T) {
	f := findings075(t, `
include:
  - project: my-group/sub/ci-templates
    ref: 1111111111111111111111111111111111111111
    file: /ci.yml
`, []string{"my-group"})
	if len(f) != 0 {
		t.Errorf("expected no finding for allowed namespace, got %d", len(f))
	}
}

func TestGL075_ProjectAllowedByExactPath(t *testing.T) {
	f := findings075(t, `
include:
  - project: my-group/ci-templates
    ref: 1111111111111111111111111111111111111111
    file: /ci.yml
`, []string{"my-group/ci-templates"})
	if len(f) != 0 {
		t.Errorf("expected no finding for exact allowed path, got %d", len(f))
	}
}

func TestGL075_NamespaceNotSubstring(t *testing.T) {
	f := findings075(t, `
include:
  - project: my-group-evil/x
    ref: 1111111111111111111111111111111111111111
    file: /ci.yml
`, []string{"my-group"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding — my-group-evil is not my-group, got %d", len(f))
	}
}

func TestGL075_RemoteDisallowed(t *testing.T) {
	f := findings075(t, `
include:
  - remote: https://untrusted.example.com/ci.yml
`, []string{"gitlab.com"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for untrusted remote host, got %d", len(f))
	}
}

func TestGL075_RemoteAllowedByHost(t *testing.T) {
	f := findings075(t, `
include:
  - remote: https://gitlab.com/group/proj/-/raw/main/ci.yml
`, []string{"gitlab.com"})
	if len(f) != 0 {
		t.Errorf("expected no finding for allowed remote host, got %d", len(f))
	}
}

func TestGL075_RemoteAllowedByHostPathPrefix(t *testing.T) {
	clean := findings075(t, `
include:
  - remote: https://cdn.example.com/ci/templates/build.yml
`, []string{"cdn.example.com/ci"})
	if len(clean) != 0 {
		t.Errorf("expected no finding for allowed host/path prefix, got %d", len(clean))
	}
	flagged := findings075(t, `
include:
  - remote: https://cdn.example.com/other/build.yml
`, []string{"cdn.example.com/ci"})
	if len(flagged) != 1 {
		t.Fatalf("expected 1 finding for path outside allowed prefix, got %d", len(flagged))
	}
}

func TestGL075_ComponentDisallowed(t *testing.T) {
	f := findings075(t, `
include:
  - component: gitlab.com/evil-org/comp@1.0
`, []string{"gitlab.com/trusted"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for untrusted component source, got %d", len(f))
	}
}

func TestGL075_ComponentAllowed(t *testing.T) {
	f := findings075(t, `
include:
  - component: gitlab.com/trusted/comp@1.0
`, []string{"gitlab.com/trusted"})
	if len(f) != 0 {
		t.Errorf("expected no finding for allowed component source, got %d", len(f))
	}
}

func TestGL075_ComponentAllowedByHost(t *testing.T) {
	f := findings075(t, `
include:
  - component: gitlab.com/any-org/comp@1.0
`, []string{"gitlab.com"})
	if len(f) != 0 {
		t.Errorf("expected no finding when whole component host is allowed, got %d", len(f))
	}
}

func TestGL075_VariableSourceExempt(t *testing.T) {
	f := findings075(t, `
include:
  - project: $TEMPLATE_PROJECT
    ref: 1111111111111111111111111111111111111111
    file: /ci.yml
  - remote: https://$HOST/ci.yml
`, []string{"my-group"})
	if len(f) != 0 {
		t.Errorf("expected no findings for variable-expanded sources, got %d", len(f))
	}
}

func TestGL075_LocalAndTemplateIgnored(t *testing.T) {
	f := findings075(t, `
include:
  - local: /ci/build.yml
  - template: Security/SAST.gitlab-ci.yml
`, []string{"my-group"})
	if len(f) != 0 {
		t.Errorf("expected no findings for local/template includes, got %d", len(f))
	}
}

func TestGL075_SingleMappingForm(t *testing.T) {
	f := findings075(t, `
include:
  project: other-group/evil
  ref: 1111111111111111111111111111111111111111
  file: /ci.yml
`, []string{"my-group"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for single-mapping include form, got %d", len(f))
	}
}

func TestGL075_NoInclude_NoFinding(t *testing.T) {
	f := findings075(t, `
build:
  script: [make]
`, []string{"my-group"})
	if len(f) != 0 {
		t.Errorf("expected no findings without include:, got %d", len(f))
	}
}

func TestGL075_ServerRelativeComponent(t *testing.T) {
	allowed := []string{"my-group", "gitlab.com/my-group"}
	cases := []struct {
		component string
		flagged   bool
	}{
		{"$CI_SERVER_FQDN/evil/comp/a@1.0.0", true},
		{"${CI_SERVER_FQDN}/evil/comp/a@1.0.0", true},
		{"$CI_SERVER_HOST/evil/comp/a@1.0.0", true},
		{"$CI_SERVER_FQDN/my-group/comp/a@1.0.0", false},
		{"${CI_SERVER_HOST}/My-Group/sub/comp@1.0.0", false},
		{"$CI_SERVER_FQDN/my-groupevil/comp@1.0.0", true},
		{"$CI_SERVER_FQDN/$CI_PROJECT_PATH/my-component@1.0.0", false},
		{"$CI_SERVER_FQDN/${CI_PROJECT_ROOT_NAMESPACE}/ci/comp@1.0.0", false},
		{"$CI_SERVER_FQDN/$CI_PROJECT_NAMESPACE/comp@1.0.0", false},
		{"$CI_SERVER_FQDN/$OTHER_GROUP/comp@1.0.0", false}, // unresolvable
		{"$CI_SERVER_FQDN/my-group/../evil/comp@1.0.0", true},
	}
	for _, tc := range cases {
		f := findings075(t, "include:\n  - component: "+tc.component+"\n", allowed)
		if got := len(f) > 0; got != tc.flagged {
			t.Errorf("%s: flagged=%v, want %v", tc.component, got, tc.flagged)
		}
	}
}

func TestGL075_ServerRelativeEntries(t *testing.T) {
	src := "include:\n  - component: $CI_SERVER_FQDN/platform/ci/build@2.0.0\n"
	cases := []struct {
		entry   string
		allowed bool
	}{
		{"$CI_SERVER_FQDN/platform", true},
		{"${CI_SERVER_HOST}/platform/ci", true},
		{"platform/ci", true},
		{"platform/other", false},
		{"gitlab.com/platform", false}, // the instance host is unknown statically
		{"gitlab.com", false},
	}
	for _, tc := range cases {
		f := findings075(t, src, []string{tc.entry})
		if got := len(f) == 0; got != tc.allowed {
			t.Errorf("entry %q: allowed=%v, want %v", tc.entry, got, tc.allowed)
		}
	}
}

func TestGL075_DotSegmentsNeverAllowed(t *testing.T) {
	allowed := []string{"my-group", "gitlab.com/my-group"}
	for _, item := range []string{
		"component: gitlab.com/my-group/../evil/comp/a@1.0.0",
		"component: gitlab.com/my-group/%2e%2e/evil/comp/a@1.0.0",
		"component: gitlab.com/my-group/%2E./evil/comp/a@1.0.0",
		"remote: https://gitlab.com/my-group/../evil/raw/a.yml",
		"project: my-group/../evil/ci\n    ref: 1111111111111111111111111111111111111111\n    file: /a.yml",
		"project: my-group/./ci\n    ref: 1111111111111111111111111111111111111111\n    file: /a.yml",
	} {
		f := findings075(t, "include:\n  - "+item+"\n", allowed)
		if len(f) != 1 || !strings.Contains(f[0].Message, "path segment") {
			t.Errorf("%s: expected a dot-segment finding, got %+v", item, f)
		}
	}
	// A dot inside a segment is an ordinary name.
	f := findings075(t, "include:\n  - project: my-group/ci.templates\n    ref: 1111111111111111111111111111111111111111\n    file: /a.yml\n", allowed)
	if len(f) != 0 {
		t.Errorf("expected no finding for a dotted project name, got %d", len(f))
	}
}
