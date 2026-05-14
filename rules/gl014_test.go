package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings014(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL014.Check(doc.Root, "test.yml")
}

func TestGL014_EnvDumpWithDotenv(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - make build
    - env > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL014_PrintenvDumpWithDotenv(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - printenv > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for printenv >, got %d", len(f))
	}
}

func TestGL014_EnvDumpNoDotenv_NoFinding(t *testing.T) {
	// env > file without dotenv artifact is not our concern
	f := findings014(t, `
build:
  script:
    - env > build.env
    - make build
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when no dotenv artifact, got %d", len(f))
	}
}

func TestGL014_DotenvNoEnvDump_NoFinding(t *testing.T) {
	// dotenv artifact with specific vars is safe
	f := findings014(t, `
build:
  script:
    - echo "BUILD_VERSION=$BUILD_VERSION" > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for specific var export, got %d", len(f))
	}
}

func TestGL014_BeforeScript(t *testing.T) {
	f := findings014(t, `
build:
  before_script:
    - env > vars.env
  script:
    - make
  artifacts:
    reports:
      dotenv: vars.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for env dump in before_script, got %d", len(f))
	}
}

func TestGL014_OneFindingPerJob(t *testing.T) {
	// Both script lines match but only one finding should be emitted per job
	f := findings014(t, `
build:
  script:
    - env > build.env
    - printenv > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding per job, got %d", len(f))
	}
}

func TestGL014_MultipleJobs(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - env > build.env
  artifacts:
    reports:
      dotenv: build.env

test:
  script:
    - env > test.env
  artifacts:
    reports:
      dotenv: test.env
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for two jobs, got %d", len(f))
	}
}

func TestGL014_LineNumber(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - make build
    - env > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
