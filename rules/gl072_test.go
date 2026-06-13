package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings072rule(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL072.Check(doc.Root, "test.yml")
}

func TestGL072_MutableRef(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - project: ns/group/project
      job: build-1
      ref: main
      artifacts: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mutable ref, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
	if strings.Contains(f[0].Message, "variable") {
		t.Errorf("expected mutable-ref message, got variable message: %q", f[0].Message)
	}
}

func TestGL072_VariableRef(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - project: ns/group/project
      job: build-1
      ref: $ARTIFACTS_DOWNLOAD_REF
      artifacts: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for variable ref, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "variable") {
		t.Errorf("expected variable-specific message, got %q", f[0].Message)
	}
}

func TestGL072_VariableRefBraced(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - project: ns/group/project
      job: build-1
      ref: ${DOWNLOAD_REF}
      artifacts: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ${VAR} ref, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "variable") {
		t.Errorf("expected variable-specific message, got %q", f[0].Message)
	}
}

func TestGL072_ShaRef_NoFinding(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - project: ns/group/project
      job: build-1
      ref: 3fa92b1c4d5e6f7081920a1b2c3d4e5f60718293
      artifacts: true
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned SHA ref, got %d", len(f))
	}
}

func TestGL072_TagRef_NoFinding(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - project: ns/group/project
      job: build-1
      ref: v1.2.3
      artifacts: true
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for tag ref, got %d", len(f))
	}
}

func TestGL072_PlainNeeds_NoFinding(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - other_job
    - job: another_job
`)
	if len(f) != 0 {
		t.Errorf("plain same-pipeline needs — expected no finding, got %d", len(f))
	}
}

func TestGL072_NeedsPipeline_NoFinding(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - pipeline: other/project
      job: build-1
`)
	if len(f) != 0 {
		t.Errorf("needs:pipeline is out of scope — expected no finding, got %d", len(f))
	}
}

func TestGL072_ArtifactsFalse_NoFinding(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - project: ns/group/project
      job: build-1
      ref: main
      artifacts: false
`)
	if len(f) != 0 {
		t.Errorf("artifacts: false downloads nothing — expected no finding, got %d", len(f))
	}
}

func TestGL072_ArtifactsAbsentDefaultsTrue(t *testing.T) {
	// For needs:project, artifacts defaults to true, so an absent key still downloads.
	f := findings072rule(t, `
build_job:
  needs:
    - project: ns/group/project
      job: build-1
      ref: main
`)
	if len(f) != 1 {
		t.Fatalf("absent artifacts defaults to true — expected 1 finding, got %d", len(f))
	}
}

func TestGL072_MultipleNeeds(t *testing.T) {
	f := findings072rule(t, `
build_job:
  needs:
    - other_job
    - project: ns/a
      job: build
      ref: develop
      artifacts: true
    - project: ns/b
      job: build
      ref: 3fa92b1c4d5e6f7081920a1b2c3d4e5f60718293
      artifacts: true
    - project: ns/c
      job: build
      ref: $REF
      artifacts: true
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (develop + $REF), got %d", len(f))
	}
}

func TestGL072_NoNeeds_NoFinding(t *testing.T) {
	f := findings072rule(t, `
build_job:
  script:
    - make build
`)
	if len(f) != 0 {
		t.Errorf("no needs — expected no finding, got %d", len(f))
	}
}

func TestGL072_JobNameSet(t *testing.T) {
	f := findings072rule(t, `
my_build:
  needs:
    - project: ns/group/project
      job: build-1
      ref: main
      artifacts: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Job != "my_build" {
		t.Errorf("expected Job=my_build, got %q", f[0].Job)
	}
}
