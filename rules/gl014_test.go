// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
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

func TestGL014_DumpIntoArtifact(t *testing.T) {
	cases := map[string]struct{ script, artifacts string }{
		"env, file in paths":       {"env > diagnostics.txt", "paths: [diagnostics.txt]"},
		"printenv append":          {"printenv >> logs/env.txt", "paths: [logs/]"},
		"export -p":                {"export -p > vars.sh", "paths: [\"*.sh\"]"},
		"proc environ":             {"cat /proc/self/environ > environ.bin", "paths: [environ.bin]"},
		"tee":                      {"env | tee out/env.log", "paths: [out]"},
		"tee append":               {"printenv | tee -a out/env.log", "paths: [\"out/*.log\"]"},
		"doublestar":               {"env > reports/ci/env.txt", "paths: [\"**/*.txt\"]"},
		"whole directory":          {"env > env.txt", "paths: [.]"},
		"dot slash":                {"env > ./env.txt", "paths: [\"./env.txt\"]"},
		"project dir variable":     {"env > $CI_PROJECT_DIR/env.txt", "paths: [env.txt]"},
		"untracked":                {"env > env.txt", "untracked: true"},
		"untracked, unknown file":  {"env > $OUT_FILE", "untracked: true"},
		"after another command":    {"make build && env > env.txt", "paths: [env.txt]"},
		"quoted target":            {`env > "env.txt"`, "paths: [env.txt]"},
		"glob directory component": {"env > build-1/env.txt", "paths: [\"build-*\"]"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings014(t, fmt.Sprintf(`
diag:
  script:
    - %q
  artifacts:
    %s
    expire_in: 1 day
`, tc.script, tc.artifacts))
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "artifacts upload") {
				t.Errorf("unexpected finding: %+v", f[0])
			}
		})
	}
}

func TestGL014_DumpNotInArtifact_NoFinding(t *testing.T) {
	cases := map[string]struct{ script, artifacts string }{
		"other file":              {"env > diagnostics.txt", "paths: [dist/]"},
		"excluded":                {"env > out/env.txt", "paths: [out/]\n    exclude: [\"out/*.txt\"]"},
		"excluded from untracked": {"env > env.txt", "untracked: true\n    exclude: [env.txt]"},
		"outside project":         {"env > /tmp/env.txt", "paths: [\"**\"]"},
		"variable target":         {"env > $OUT_FILE", "paths: [dist/]"},
		"single variable":         {"printenv HOME > home.txt", "paths: [home.txt]"},
		"filtered env":            {"env | grep ^APP_ > app.env", "paths: [app.env]"},
		"dotenv file contents":    {"cat .env > merged.env", "paths: [merged.env]"},
		"glob in one segment":     {"env > a/b/env.txt", "paths: [\"a/*.txt\"]"},
		"env runs a command":      {"env FOO=1 make > build.log", "paths: [build.log]"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings014(t, fmt.Sprintf(`
diag:
  script:
    - %q
  artifacts:
    %s
    expire_in: 1 day
`, tc.script, tc.artifacts))
			if len(f) != 0 {
				t.Fatalf("expected no finding, got %v", f)
			}
		})
	}
}

func TestGL014_DefaultArtifacts(t *testing.T) {
	f := findings014(t, `
default:
  artifacts:
    paths: [env.txt]
diag:
  script:
    - env > env.txt
`)
	if len(f) != 1 {
		t.Fatalf("expected the default: artifacts to apply, got %d findings", len(f))
	}
}

func TestGL014_DotenvMessageWins(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - env > build.env
  artifacts:
    paths: [build.env]
    reports:
      dotenv: build.env
`)
	if len(f) != 1 || !strings.Contains(f[0].Message, "dotenv") {
		t.Fatalf("expected one dotenv finding, got %v", f)
	}
}
