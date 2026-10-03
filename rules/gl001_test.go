package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL001.Check(doc.Root, "test.yml")
}

func TestGL001_MutableTag(t *testing.T) {
	f := findings(t, `
build:
  image: node:latest
  script: [npm run build]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL001_NoTag(t *testing.T) {
	f := findings(t, `
build:
  image: alpine
  script: [echo hi]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestGL001_PinnedVersion(t *testing.T) {
	f := findings(t, `
build:
  image: node:20.11.0
  script: [npm run build]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings, got %v", f)
	}
}

func TestGL001_DigestPinned(t *testing.T) {
	f := findings(t, `
build:
  image: node@sha256:abc123def456
  script: [npm run build]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for digest-pinned image")
	}
}

func TestGL001_MappingForm(t *testing.T) {
	f := findings(t, `
build:
  image:
    name: node:latest
    entrypoint: [""]
  script: [npm run build]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for mapping form, got %d", len(f))
	}
}

func TestGL001_Services(t *testing.T) {
	f := findings(t, `
build:
  image: node:20.11.0
  services:
    - docker:dind
    - name: postgres:latest
      alias: db
  script: [npm run build]
`)
	// postgres:latest is an error, docker:dind a version-less variant (warn)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (docker:dind, postgres:latest), got %d", len(f))
	}
}

func TestGL001_DefaultBlock(t *testing.T) {
	f := findings(t, `
default:
  image: ubuntu:latest
  services:
    - docker:dind

build:
  script: [make]
`)
	// ubuntu:latest is an error, docker:dind a version-less variant (warn)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings from default block, got %d", len(f))
	}
}

func TestGL001_TopLevelImage(t *testing.T) {
	f := findings(t, `
image: ruby:latest

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for top-level image, got %d", len(f))
	}
}

func TestGL001_LineNumbers(t *testing.T) {
	f := findings(t, `
build:
  image: node:latest
  script: [npm run build]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL001_Registry(t *testing.T) {
	f := findings(t, `
build:
  image: registry.company.com:5000/node:20.11.0
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for pinned registry image, got %v", f)
	}
}

func TestGL001_RegistryLatest(t *testing.T) {
	f := findings(t, `
build:
  image: registry.company.com:5000/node:latest
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for registry image with latest tag, got %d", len(f))
	}
}

func TestGL001_VariableRef(t *testing.T) {
	f := findings(t, `
variables:
  MY_IMAGE: alpine:3.19
build:
  image: $MY_IMAGE
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for image: $VARIABLE (tag cannot be determined statically), got %d", len(f))
	}
}

func TestGL001_VariableRefBrace(t *testing.T) {
	f := findings(t, `
build:
  image: ${MY_IMAGE}
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for image: ${VARIABLE}, got %d", len(f))
	}
}

func TestGL001_LtsTag(t *testing.T) {
	f := findings(t, `
build:
  image: node:lts
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for node:lts, got %d", len(f))
	}
}

func TestGL001_CurrentTag(t *testing.T) {
	f := findings(t, `
build:
  image: node:current
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for node:current, got %d", len(f))
	}
}

func TestGL001_TestingTag(t *testing.T) {
	f := findings(t, `
build:
  image: debian:testing
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for debian:testing, got %d", len(f))
	}
}

func TestGL001_LtsVariantNotFlagged(t *testing.T) {
	f := findings(t, `
build:
  image: node:20-alpine
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for node:20-alpine (pinned version), got %d", len(f))
	}
}

func TestGL001_VersionlessTags_Warn(t *testing.T) {
	for _, ref := range []string{
		"docker:dind",
		"docker:dind-rootless",
		"docker:cli",
		"node:alpine",
		"python:slim",
		"debian:bookworm",
		"registry.example.com:5000/team/builder:ci",
	} {
		f := findings(t, "job:\n  image: "+ref+"\n  script: [make]\n")
		if len(f) != 1 {
			t.Errorf("%s: expected 1 finding, got %d", ref, len(f))
			continue
		}
		if f[0].Severity != finding.Warn {
			t.Errorf("%s: expected Warn, got %s", ref, f[0].Severity)
		}
		if !strings.Contains(f[0].Message, "names no version") {
			t.Errorf("%s: unexpected message %q", ref, f[0].Message)
		}
	}
}

func TestGL001_VersionedOrUnknownTags_NoFinding(t *testing.T) {
	for _, ref := range []string{
		"docker:27-dind",
		"docker:27.3.1-dind-rootless",
		"python:3.11-slim",
		"node:20.11.0-alpine",
		"ubuntu:24.04",
		"alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
		"docker:dind@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
		"$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA",
		"myimage:${VERSION}",
		"builder:$TAG-alpine",
		"$BUILD_IMAGE",
	} {
		if f := findings(t, "job:\n  image: \""+ref+"\"\n  script: [make]\n"); len(f) != 0 {
			t.Errorf("%s: expected no finding, got %q", ref, f[0].Message)
		}
	}
}

func TestGL001_LatestStaysError(t *testing.T) {
	f := findings(t, "job:\n  image: node:latest\n  script: [make]\n")
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error for node:latest, got %+v", f)
	}
}

func TestGL001_ResolvesFileVariables(t *testing.T) {
	f := findings(t, `
variables:
  BASE_IMAGE: node:latest
  DIND:
    value: docker:dind
    description: daemon image
global:
  image: $BASE_IMAGE
  services: [$DIND]
  script: [echo hi]
jobvar:
  variables:
    JIMG: ruby:latest
  image: ${JIMG}
  script: [echo hi]
matrix:
  image:
    name: $IMG
  parallel:
    matrix:
      - IMG: ["golang:latest", "alpine", "golang:1.23"]
      - IMG: golang:latest
  script: [echo hi]
`)
	want := []string{
		`"$BASE_IMAGE" (= "node:latest")`,
		`"$DIND" (= "docker:dind")`,
		`"${JIMG}" (= "ruby:latest")`,
		`"$IMG" (= "golang:latest")`,
		`"$IMG" (= "alpine")`,
	}
	if len(f) != len(want) {
		for _, x := range f {
			t.Log(x.Message)
		}
		t.Fatalf("expected %d findings, got %d", len(want), len(f))
	}
	for i, w := range want {
		if !strings.Contains(f[i].Message, w) {
			t.Errorf("finding %d: expected %s in %q", i, w, f[i].Message)
		}
	}
}

func TestGL001_ResolutionPrecedence(t *testing.T) {
	f := findings(t, `
variables:
  IMG: node:latest
job_overrides:
  variables:
    IMG: node:22.11.0
  image: $IMG
  script: [echo hi]
matrix_overrides:
  image: $IMG
  parallel:
    matrix:
      - IMG: node:22.11.0
  script: [echo hi]
matrix_partial:
  image: $IMG
  parallel:
    matrix:
      - IMG: node:22.11.0
      - OTHER: x
  script: [echo hi]
`)
	if len(f) != 1 || f[0].Job != "matrix_partial" {
		t.Fatalf("expected only matrix_partial to fall back to the global value, got %v", f)
	}
}

func TestGL001_UnresolvedVariables_NoFinding(t *testing.T) {
	f := findings(t, `
variables:
  IMG: node:latest
  NESTED: $CI_REGISTRY/node
  PUSH_TARGET: registry.example.com/app:latest
undefined:
  image: $NOT_IN_FILE
  script: [echo hi]
nested:
  image: $NESTED
  script: [echo hi]
inherit_off:
  inherit:
    variables: false
  image: $IMG
  script: [echo hi]
inherit_list:
  inherit:
    variables: [OTHER]
  image: $IMG
  script: [echo hi]
extends_job:
  extends: .base
  image: $IMG
  script: [echo hi]
.template:
  image: $IMG
  script: [echo hi]
push:
  image: docker:27.3.1
  script: [docker push $PUSH_TARGET]
`)
	if len(f) != 0 {
		for _, x := range f {
			t.Log(x.Job, x.Message)
		}
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestGL001_GitLabMacOSImage_NoFinding(t *testing.T) {
	f := findings(t, `
variables:
  MAC_IMAGE: macos-15-xcode-16
mac:
  image: macos-14-xcode-15
  tags: [saas-macos-medium-m1]
  script: [xcodebuild]
mac_var:
  image: $MAC_IMAGE
  tags: [saas-macos-medium-m1]
  script: [xcodebuild]
other:
  image: macos-builder
  script: [echo hi]
`)
	if len(f) != 1 || f[0].Job != "other" {
		t.Fatalf("expected only the non-GitLab image to be flagged, got %v", f)
	}
}
