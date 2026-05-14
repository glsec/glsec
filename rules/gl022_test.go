package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings022(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL022.Check(doc.Root, "test.yml")
}

// --- pip ---

func TestGL022_PipUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - pip install ansible
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned pip install, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL022_PipPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - pip install ansible==9.2.0
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned pip install, got %d", len(f))
	}
}

func TestGL022_PipRequirementsFile_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - pip install -r requirements.txt
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pip install -r, got %d", len(f))
	}
}

func TestGL022_PipUpgrade(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - pip install --upgrade ansible
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for pip --upgrade, got %d", len(f))
	}
}

func TestGL022_PipLocalPackage_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - pip install .
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pip install . (local), got %d", len(f))
	}
}

// --- npm ---

func TestGL022_NpmGlobalUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - npm install -g typescript
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned npm install -g, got %d", len(f))
	}
}

func TestGL022_NpmGlobalPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - npm install -g typescript@5.4.5
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned npm install -g, got %d", len(f))
	}
}

func TestGL022_NpmScopedUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - npm install -g @angular/cli
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for scoped npm package without version, got %d", len(f))
	}
}

func TestGL022_NpmScopedPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - npm install -g @angular/cli@17.3.6
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for scoped npm package with version, got %d", len(f))
	}
}

func TestGL022_NpmUpdate(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - npm update
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for npm update, got %d", len(f))
	}
}

func TestGL022_NpmInstallLocal_NoFinding(t *testing.T) {
	// npm install without -g installs from package.json — covered by GL023
	f := findings022(t, `
build:
  script:
    - npm install
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for npm install (local), got %d", len(f))
	}
}

// --- apt-get ---

func TestGL022_AptGetUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - apt-get install -y jq
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned apt-get install, got %d", len(f))
	}
}

func TestGL022_AptGetPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - apt-get install -y jq=1.6-2
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned apt-get install, got %d", len(f))
	}
}

// --- apk ---

func TestGL022_ApkUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - apk add --no-cache curl
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned apk add, got %d", len(f))
	}
}

func TestGL022_ApkPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - apk add --no-cache curl=8.5.0-r0
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned apk add, got %d", len(f))
	}
}

// --- gem ---

func TestGL022_GemUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - gem install bundler
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned gem install, got %d", len(f))
	}
}

func TestGL022_GemPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - gem install bundler -v 2.5.6
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned gem install, got %d", len(f))
	}
}

// --- cargo ---

func TestGL022_CargoUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - cargo install cargo-audit
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned cargo install, got %d", len(f))
	}
}

func TestGL022_CargoPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - cargo install cargo-audit --version 0.20.0
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned cargo install, got %d", len(f))
	}
}

// --- update commands ---

func TestGL022_ComposerUpdate(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - composer update
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for composer update, got %d", len(f))
	}
}

func TestGL022_BundleUpdate(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - bundle update
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for bundle update, got %d", len(f))
	}
}

func TestGL022_CargoUpdate(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - cargo update
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for cargo update, got %d", len(f))
	}
}

// --- general ---

func TestGL022_LineNumber(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - pip install ansible
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
