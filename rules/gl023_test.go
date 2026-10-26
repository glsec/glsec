// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
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
