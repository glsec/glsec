package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings054(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL054.Check(doc.Root, "test.yml")
}

func TestGL054_DinDServiceScalar(t *testing.T) {
	f := findings054(t, `
build-image:
  services:
    - docker:26.0-dind
  script:
    - docker build -t myapp .
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL054" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
	if f[0].Job != "build-image" {
		t.Errorf("expected job build-image, got %q", f[0].Job)
	}
}

func TestGL054_DinDServiceBareTag(t *testing.T) {
	f := findings054(t, `
build:
  services:
    - docker:dind
  script: [docker build .]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for docker:dind, got %d", len(f))
	}
}

func TestGL054_DinDServiceMappingForm(t *testing.T) {
	f := findings054(t, `
build:
  services:
    - name: docker:24-dind
      alias: docker
  script: [docker build .]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mapping-form dind service, got %d", len(f))
	}
}

func TestGL054_DinDServiceRegistryPrefixed(t *testing.T) {
	f := findings054(t, `
build:
  services:
    - docker.io/library/docker:dind
  script: [docker build .]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for registry-prefixed dind, got %d", len(f))
	}
}

func TestGL054_DockerHostVariableOnly(t *testing.T) {
	f := findings054(t, `
build:
  image: docker:26.0
  variables:
    DOCKER_HOST: tcp://docker:2375
  script: [docker build .]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for DOCKER_HOST, got %d", len(f))
	}
}

func TestGL054_ServiceAndDockerHostDeduped(t *testing.T) {
	f := findings054(t, `
build-image:
  services:
    - docker:26.0-dind
  variables:
    DOCKER_HOST: tcp://docker:2375
  script: [docker build .]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding when both service and DOCKER_HOST present, got %d", len(f))
	}
}

func TestGL054_NonDinDDockerImage(t *testing.T) {
	f := findings054(t, `
build:
  image: docker:26.0
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
  script: [docker build .]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for socket-binding docker (no dind), got %d", len(f))
	}
}

func TestGL054_Kaniko(t *testing.T) {
	f := findings054(t, `
build-image:
  image:
    name: gcr.io/kaniko-project/executor:v1.21.0-debug
    entrypoint: [""]
  script:
    - /kaniko/executor --context . --destination myapp
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for Kaniko, got %d", len(f))
	}
}
