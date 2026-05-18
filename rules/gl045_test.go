package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings045(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL045.Check(doc.Root, "test.yml")
}

func TestGL045_DockerPushWithoutSigning(t *testing.T) {
	f := findings045(t, `
publish:
  stage: release
  script:
    - docker build -t registry.example.com/app:$CI_COMMIT_TAG .
    - docker push registry.example.com/app:$CI_COMMIT_TAG
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL045_DockerPushWithCosignNoFinding(t *testing.T) {
	f := findings045(t, `
publish:
  stage: release
  script:
    - docker push registry.example.com/app:$CI_COMMIT_TAG
    - cosign sign --key $COSIGN_KEY registry.example.com/app:$CI_COMMIT_TAG
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when cosign sign present, got %d", len(f))
	}
}

func TestGL045_DockerPushWithGPGNoFinding(t *testing.T) {
	f := findings045(t, `
publish:
  stage: release
  script:
    - docker push registry.example.com/app:$CI_COMMIT_TAG
    - gpg --detach-sign dist/app.tar.gz
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when gpg --detach-sign present, got %d", len(f))
	}
}

func TestGL045_NpmPublishWithoutSigning(t *testing.T) {
	f := findings045(t, `
release-npm:
  script:
    - npm publish
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for npm publish without signing, got %d", len(f))
	}
}

func TestGL045_CargoPublishWithoutSigning(t *testing.T) {
	f := findings045(t, `
publish-crate:
  stage: publish
  script:
    - cargo publish
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for cargo publish without signing, got %d", len(f))
	}
}

func TestGL045_GoreleaserWithoutSigning(t *testing.T) {
	f := findings045(t, `
release:
  script:
    - goreleaser release --clean
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for goreleaser release without signing, got %d", len(f))
	}
}

func TestGL045_TwineUploadWithoutSigning(t *testing.T) {
	f := findings045(t, `
upload-pypi:
  stage: upload
  script:
    - twine upload dist/*
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for twine upload without signing, got %d", len(f))
	}
}

func TestGL045_NotationSignNoFinding(t *testing.T) {
	f := findings045(t, `
publish:
  stage: release
  script:
    - docker push registry.example.com/app:$CI_COMMIT_TAG
    - notation sign registry.example.com/app:$CI_COMMIT_TAG
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when notation sign present, got %d", len(f))
	}
}

func TestGL045_SigningInBeforeScriptNoFinding(t *testing.T) {
	f := findings045(t, `
publish:
  stage: release
  before_script:
    - cosign sign --key $COSIGN_KEY registry.example.com/app:$CI_COMMIT_TAG
  script:
    - docker push registry.example.com/app:$CI_COMMIT_TAG
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when signing in before_script, got %d", len(f))
	}
}

func TestGL045_NonReleaseJobNoFinding(t *testing.T) {
	f := findings045(t, `
build:
  stage: build
  script:
    - docker build -t myapp .
    - docker push registry.internal/myapp:latest
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for non-release job, got %d", len(f))
	}
}

func TestGL045_NoPushCommandNoFinding(t *testing.T) {
	f := findings045(t, `
release:
  script:
    - make build
    - ./create-release.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without push command, got %d", len(f))
	}
}

func TestGL045_StageNameMatchNoFinding(t *testing.T) {
	f := findings045(t, `
build-image:
  stage: release
  script:
    - docker push registry.example.com/app:$CI_COMMIT_TAG
    - cosign sign --key $COSIGN_KEY registry.example.com/app:$CI_COMMIT_TAG
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when job matches via stage and has signing, got %d", len(f))
	}
}

func TestGL045_HelmPushWithoutSigning(t *testing.T) {
	f := findings045(t, `
publish-chart:
  stage: release
  script:
    - helm push mychart-1.0.0.tgz oci://registry.example.com/charts
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for helm push without signing, got %d", len(f))
	}
}
