package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings055(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL055.Check(doc.Root, "test.yml")
}

func TestGL055_SocketVolumeMount(t *testing.T) {
	f := findings055(t, `
build:
  services:
    - name: docker:dind
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock
  script: [docker build .]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for socket volume mount, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL055" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
	if f[0].Job != "build" {
		t.Errorf("expected job build, got %q", f[0].Job)
	}
}

func TestGL055_DockerHostUnixSocket(t *testing.T) {
	f := findings055(t, `
build:
  image: docker:26.0
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
  script: [docker build .]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for DOCKER_HOST socket, got %d", len(f))
	}
}

func TestGL055_VolumeAndDockerHostDeduped(t *testing.T) {
	f := findings055(t, `
build:
  variables:
    DOCKER_HOST: unix:///var/run/docker.sock
  services:
    - name: docker:dind
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock
  script: [docker build .]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding when both socket signals present, got %d", len(f))
	}
}

func TestGL055_TCPDockerHostNotFlagged(t *testing.T) {
	f := findings055(t, `
build:
  services:
    - docker:dind
  variables:
    DOCKER_HOST: tcp://docker:2376
  script: [docker build .]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for TLS tcp DOCKER_HOST (that is GL054's job), got %d", len(f))
	}
}

func TestGL055_NonSocketVolume(t *testing.T) {
	f := findings055(t, `
build:
  services:
    - name: docker:dind
      volumes:
        - /cache:/cache
  script: [docker build .]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for unrelated volume, got %d", len(f))
	}
}

func TestGL055_Clean(t *testing.T) {
	f := findings055(t, `
test:
  image: golang:1.24
  script: [go test ./...]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for clean pipeline, got %d", len(f))
	}
}
