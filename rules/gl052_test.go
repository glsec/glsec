package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings052(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL052.Check(doc.Root, "test.yml")
}

func TestGL052_CommitRefNameInEnvName(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment:
    name: review/$CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
	if f[0].Job != "deploy" {
		t.Errorf("expected job 'deploy', got %q", f[0].Job)
	}
}

func TestGL052_CommitRefSlugInEnvName(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment:
    name: review/$CI_COMMIT_REF_SLUG
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_REF_SLUG, got %d", len(f))
	}
}

func TestGL052_CommitBranchInEnvName(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment:
    name: deploy-$CI_COMMIT_BRANCH
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_BRANCH, got %d", len(f))
	}
}

func TestGL052_MRSourceBranchInEnvName(t *testing.T) {
	f := findings052(t, `
review:
  script:
    - ./deploy.sh
  environment:
    name: $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_MERGE_REQUEST_SOURCE_BRANCH_NAME, got %d", len(f))
	}
}

func TestGL052_ScalarEnvironmentShorthand(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment: review/$CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for scalar environment shorthand, got %d", len(f))
	}
}

func TestGL052_StaticEnvName_NoFinding(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment:
    name: production
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for static environment name, got %d", len(f))
	}
}

func TestGL052_NoEnvironment_NoFinding(t *testing.T) {
	f := findings052(t, `
build:
  script:
    - make build
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without environment, got %d", len(f))
	}
}

func TestGL052_BraceForm(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment:
    name: review/${CI_COMMIT_REF_NAME}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace form, got %d", len(f))
	}
}

func TestGL052_DeduplicateSameVar(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment:
    name: $CI_COMMIT_REF_NAME-$CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (deduped), got %d", len(f))
	}
}

func TestGL052_MultipleVars(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment:
    name: $CI_COMMIT_BRANCH/$CI_MERGE_REQUEST_TITLE
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for two user-controlled vars, got %d", len(f))
	}
}

func TestGL052_URLInEnvName_NoFinding(t *testing.T) {
	f := findings052(t, `
deploy:
  script:
    - ./deploy.sh
  environment:
    name: production
    url: https://prod.example.com
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for static env name with url, got %d", len(f))
	}
}
