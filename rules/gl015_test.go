package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings015(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL015.Check(doc.Root, "test.yml")
}

func TestGL015_DockerBuildRefSlug(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG .
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL015_DockerPushRefName(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for docker push with ref name, got %d", len(f))
	}
}

func TestGL015_DockerBuildBranch(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - docker build -t registry.example.com/app:$CI_COMMIT_BRANCH .
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_BRANCH, got %d", len(f))
	}
}

func TestGL015_PodmanBuild(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - podman build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG .
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for podman build, got %d", len(f))
	}
}

func TestGL015_BraceForm(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - docker push $CI_REGISTRY_IMAGE:${CI_COMMIT_REF_SLUG}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace form, got %d", len(f))
	}
}

func TestGL015_SafeSHA_NoFinding(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for SHA tag, got %d", len(f))
	}
}

func TestGL015_SafeShortSHA_NoFinding(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA .
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for short SHA tag, got %d", len(f))
	}
}

func TestGL015_BuildArgOnly_NoFinding(t *testing.T) {
	// Using user-controlled var as a build arg, not as a tag — not flagged
	f := findings015(t, `
build:
  script:
    - docker build --build-arg BRANCH=$CI_COMMIT_REF_NAME .
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for build arg usage, got %d", len(f))
	}
}

func TestGL015_NonDockerCommand_NoFinding(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - echo "Branch is $CI_COMMIT_REF_SLUG"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-docker command, got %d", len(f))
	}
}

func TestGL015_LineNumber(t *testing.T) {
	f := findings015(t, `
build:
  script:
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_REF_SLUG
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
