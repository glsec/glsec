// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings023(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL023.Check(doc.Root, "test.yml")
}

// --- npm ---

func TestGL023_NpmInstall(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - npm install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for npm install, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL023_NpmInstallWithFlags(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - npm install --production
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for npm install --production, got %d", len(f))
	}
}

func TestGL023_NpmCi_NoFinding(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - npm ci
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for npm ci, got %d", len(f))
	}
}

func TestGL023_NpmInstallPackage_NoFinding(t *testing.T) {
	// Installing a specific package is GL022's territory, not GL023
	f := findings023(t, `
build:
  script:
    - npm install typescript
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for npm install <package>, got %d", len(f))
	}
}

func TestGL023_NpmInstallGlobal_NoFinding(t *testing.T) {
	// Global installs are GL022's territory
	f := findings023(t, `
build:
  script:
    - npm install -g typescript
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for npm install -g (covered by GL022), got %d", len(f))
	}
}

// --- yarn ---

func TestGL023_YarnInstall(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - yarn install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for yarn install, got %d", len(f))
	}
}

func TestGL023_YarnFrozen_NoFinding(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - yarn install --frozen-lockfile
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for yarn install --frozen-lockfile, got %d", len(f))
	}
}

func TestGL023_YarnImmutable_NoFinding(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - yarn install --immutable
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for yarn install --immutable (Yarn Berry), got %d", len(f))
	}
}

// --- pnpm ---

// pnpm freezes the lockfile by itself when CI is set, as it is in GitLab.
func TestGL023_PnpmInstall_NoFinding(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - pnpm install
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for pnpm install, got %d", len(f))
	}
}

func TestGL023_BundlerFrozenBeforehand(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"config set frozen", `
build:
  script:
    - bundle config set --global frozen 'true'
    - bundle install
`, 0},
		{"config set deployment", `
build:
  script:
    - bundle config set deployment true
    - bundle install
`, 0},
		{"BUNDLE_FROZEN job variable", `
build:
  variables:
    BUNDLE_FROZEN: "true"
  script:
    - bundle install
`, 0},
		{"BUNDLE_DEPLOYMENT global variable", `
variables:
  BUNDLE_DEPLOYMENT: "1"
build:
  script:
    - bundle install
`, 0},
		{"BUNDLE_FROZEN from extends", `
.ruby:
  variables:
    BUNDLE_FROZEN: "true"
build:
  extends: .ruby
  script:
    - bundle install
`, 0},
		{"config after the install", `
build:
  script:
    - bundle install
    - bundle config set frozen true
`, 1},
		{"frozen false", `
build:
  variables:
    BUNDLE_FROZEN: "false"
  script:
    - bundle install
`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings023(t, tc.yaml); len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d", tc.want, len(f))
			}
		})
	}
}

func TestGL023_PnpmFrozen_NoFinding(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - pnpm install --frozen-lockfile
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pnpm install --frozen-lockfile, got %d", len(f))
	}
}

// --- bundler ---

func TestGL023_BundleInstall(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - bundle install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for bundle install, got %d", len(f))
	}
}

func TestGL023_BundleFrozen_NoFinding(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - bundle install --frozen
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for bundle install --frozen, got %d", len(f))
	}
}

func TestGL023_BundleDeployment_NoFinding(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - bundle install --deployment
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for bundle install --deployment, got %d", len(f))
	}
}

// --- general ---

func TestGL023_MultipleJobs(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - npm ci

test:
  script:
    - yarn install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (yarn, not npm ci), got %d", len(f))
	}
}

func TestGL023_LineNumber(t *testing.T) {
	f := findings023(t, `
build:
  script:
    - npm install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

// BUNDLE_FROZEN inherited via extends: still suppresses the finding when the
// child job defines its own variables: block for an unrelated key — GitLab
// merges the two, it doesn't drop the inherited value (#1102).
func TestGL023_InheritedFrozenWithOwnVariables(t *testing.T) {
	frozenParentOwnVars := `
.use-ruby:
  variables:
    BUNDLE_FROZEN: "true"
run_danger:
  extends: .use-ruby
  variables:
    GIT_DEPTH: "0"
  script:
    - bundle install
`
	if f := findings023(t, frozenParentOwnVars); len(f) != 0 {
		t.Errorf("inherited BUNDLE_FROZEN + own variables: expected no finding, got %+v", f)
	}

	noFrozenAnywhere := `
run_danger:
  variables:
    GIT_DEPTH: "0"
  script:
    - bundle install
`
	if f := findings023(t, noFrozenAnywhere); len(f) != 1 {
		t.Errorf("no frozen anywhere: expected 1 finding, got %d", len(f))
	}
}

func TestGL023_UvAndBun(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{"uv sync", 1},
		{"uv sync --group dev", 1},
		{"uv sync --all-groups", 1},
		{"cd app && uv sync", 1},
		{"uv venv && uv sync --extra test", 1},
		{"uv sync --locked", 0},
		{"uv sync --frozen --group dev", 0},
		{"uv sync --check", 0},
		{"uv sync --dry-run", 0},
		{"uv pip sync requirements.txt", 0},
		{"uv lock --check && uv sync", 0},
		{"UV_FROZEN=1 uv sync", 0},
		{"export UV_LOCKED=true; uv sync", 0},
		{"UV_FROZEN=0 uv sync", 1},
		{"# uv sync", 0},
		{"bun install", 1},
		{"bun i", 1},
		{"bun install # deps", 1},
		{"bun install\nbun run build", 1},
		{"bun install --ignore-scripts\nbun run build", 1},
		{"bun install --frozen-lockfile\nbun run build", 0},
		{"bun install --ignore-scripts", 1},
		{"cd cli && bun install && bun run build", 1},
		{`su - ci -c "cd cli && bun install"`, 1},
		{"bun install --frozen-lockfile", 0},
		{"bun i --frozen-lockfile", 0},
		{"bun install --production", 0},
		{"bun ci", 0},
		{"bun install -g netlify-cli", 0},
		{"bun install -g", 0},
		{"bun add lodash", 0},
		{"bun install lodash", 0},
	} {
		t.Run(tc.script, func(t *testing.T) {
			f := findings023(t, "build:\n  script:\n    - "+strconv.Quote(tc.script)+"\n")
			if len(f) != tc.want {
				t.Fatalf("got %v, want %d findings", f, tc.want)
			}
		})
	}
}

// Each command of a block counts on its own: a comment doesn't report, and a
// strict call doesn't vouch for the bare one.
func TestGL023_UvByCommand(t *testing.T) {
	f := findings023(t, "build:\n  script:\n    - |\n      # uv sync would re-lock\n      uv sync --locked\n      uv sync --extra docs\n")
	if len(f) != 1 || f[0].Line != 6 {
		t.Fatalf("got %v, want one finding on line 6", f)
	}
}

func TestGL023_UvVariables(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      int
	}{
		{"global", "variables:\n  UV_FROZEN: \"1\"\nbuild:\n  script: [uv sync]\n", 0},
		{"job", "build:\n  variables:\n    UV_LOCKED: \"true\"\n  script: [uv sync]\n", 0},
		{"yes", "build:\n  variables:\n    UV_FROZEN: \"Yes\"\n  script: [uv sync]\n", 0},
		{"value key", "variables:\n  UV_FROZEN:\n    value: \"1\"\n    description: d\nbuild:\n  script: [uv sync]\n", 0},
		{"inherited", ".t:\n  variables:\n    UV_FROZEN: \"1\"\nbuild:\n  extends: .t\n  variables:\n    OTHER: x\n  script: [uv sync]\n", 0},
		{"off", "variables:\n  UV_FROZEN: \"0\"\nbuild:\n  script: [uv sync]\n", 1},
		{"other manager's variable", "variables:\n  BUNDLE_FROZEN: \"true\"\nbuild:\n  script: [uv sync]\n", 1},
		{"uv variable leaves bundler alone", "variables:\n  UV_FROZEN: \"1\"\nbuild:\n  script: [bundle install]\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings023(t, tc.src); len(f) != tc.want {
				t.Fatalf("got %v, want %d findings", f, tc.want)
			}
		})
	}
}

// A frozen manager doesn't hide another manager on the same line.
func TestGL023_FrozenManagerKeepsOthersOnTheLine(t *testing.T) {
	f := findings023(t, "variables:\n  BUNDLE_FROZEN: \"true\"\nbuild:\n  script:\n    - bundle install && npm install\n")
	if len(f) != 1 || !strings.Contains(f[0].Message, "npm ci") {
		t.Fatalf("got %v, want the npm finding", f)
	}
}
