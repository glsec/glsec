package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings058(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL058.Check(doc.Root, "test.yml")
}

func TestGL058_NetworkHost(t *testing.T) {
	f := findings058(t, `
test:
  script:
    - docker run --network host myimage ./integration-test.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL058" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL058_NetHostShortFlag(t *testing.T) {
	f := findings058(t, `
test:
  script:
    - docker run --net host myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --net host, got %d", len(f))
	}
}

func TestGL058_EqualsForm(t *testing.T) {
	f := findings058(t, `
test:
  script:
    - docker run --network=host myimage
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --network=host, got %d", len(f))
	}
}

func TestGL058_NamedNetworkNotFlagged(t *testing.T) {
	f := findings058(t, `
test:
  script:
    - docker network create test-net
    - docker run --network test-net myimage ./integration-test.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for named network, got %d", len(f))
	}
}

func TestGL058_HostPrefixedNetworkNotFlagged(t *testing.T) {
	f := findings058(t, `
test:
  script:
    - docker run --network host-internal myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for network named host-internal, got %d", len(f))
	}
}

func TestGL058_NoDockerRun(t *testing.T) {
	f := findings058(t, `
test:
  script:
    - echo "use --network host for perf"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without docker run, got %d", len(f))
	}
}

func TestGL058_CommentNotFlagged(t *testing.T) {
	f := findings058(t, `
test:
  script:
    - "# docker run --network host is discouraged"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}
