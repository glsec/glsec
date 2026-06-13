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

// --- yum ---

func TestGL022_YumUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - yum install -y httpd
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned yum install, got %d", len(f))
	}
}

func TestGL022_YumPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - yum install -y httpd-2.4.6
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned yum install, got %d", len(f))
	}
}

// --- dnf ---

func TestGL022_DnfUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - dnf install -y nginx
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned dnf install, got %d", len(f))
	}
}

func TestGL022_DnfPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - dnf install -y nginx-1.20.1
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned dnf install, got %d", len(f))
	}
}

// --- zypper ---

func TestGL022_ZypperUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - zypper install -y curl
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned zypper install, got %d", len(f))
	}
}

func TestGL022_ZypperInUnpinned(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - zypper in -y curl
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unpinned zypper in, got %d", len(f))
	}
}

func TestGL022_ZypperPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - zypper install -y curl=7.66.0
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned zypper install, got %d", len(f))
	}
}

func TestGL022_ZypperInfo_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - zypper info curl
`)
	if len(f) != 0 {
		t.Errorf("zypper info is not an install — expected no finding, got %d", len(f))
	}
}

// --- go install ---

func TestGL022_GoInstallLatest(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - go install golang.org/x/tools/cmd/goimports@latest
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for go install @latest, got %d", len(f))
	}
}

func TestGL022_GoInstallNoVersion(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - go install github.com/golangci/golangci-lint/cmd/golangci-lint
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for go install without @version, got %d", len(f))
	}
}

func TestGL022_GoInstallPinned_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - go install golang.org/x/tools/cmd/goimports@v0.21.0
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned go install, got %d", len(f))
	}
}

func TestGL022_GoInstallLocalPath_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - go install ./cmd/foo
`)
	if len(f) != 0 {
		t.Errorf("local go install needs no version — expected no finding, got %d", len(f))
	}
}

func TestGL022_GoInstallNoArgs_NoFinding(t *testing.T) {
	f := findings022(t, `
build:
  script:
    - go install
`)
	if len(f) != 0 {
		t.Errorf("go install with no module builds the local package — expected no finding, got %d", len(f))
	}
}

// --- variable package tokens (no FP) ---

func TestGL022_VariablePackageToken_NoFinding(t *testing.T) {
	for _, line := range []string{
		"yum install -y $PKG",
		"dnf install ${PKG}",
		"zypper install $PKG",
		"go install $TOOL",
		"apt-get install -y $PKG",
		"pip install ${PACKAGE}",
	} {
		if got := checkPMLine(line, "test.yml", 1, 1); got != nil {
			t.Errorf("expected no finding for variable package token %q, got %+v", line, got)
		}
	}
}

func TestGL022_VariableNotPackageToken_StillFlagged(t *testing.T) {
	// The package (cargo-audit) is a literal; the variable is only a flag value.
	f := findings022(t, `
build:
  script:
    - cargo install cargo-audit --root $HOME/.local
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding when only a flag value is a variable, got %d", len(f))
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

// --- composer require ---

func TestGL022_ComposerRequireUnpinned(t *testing.T) {
	f := findings022(t, `
api:
  script:
    - composer require guzzlehttp/guzzle --no-interaction
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL022_ComposerRequireUnpinnedWithDevFlag(t *testing.T) {
	f := findings022(t, `
api:
  script:
    - composer require --dev phpunit/phpunit --no-interaction --no-scripts
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for --dev without version, got %d", len(f))
	}
}

func TestGL022_ComposerRequirePinned_NoFinding(t *testing.T) {
	f := findings022(t, `
api:
  script:
    - composer require guzzlehttp/guzzle:^7.0 --no-interaction
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for pinned version, got %d", len(f))
	}
}

func TestGL022_ComposerRequirePinnedQuoted_NoFinding(t *testing.T) {
	f := findings022(t, `
api:
  script:
    - composer require "guzzlehttp/guzzle:>=7.0" --no-interaction
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for quoted pinned version, got %d", len(f))
	}
}

func TestGL022_ComposerInstall_NoFinding(t *testing.T) {
	f := findings022(t, `
api:
  script:
    - composer install --no-interaction
`)
	if len(f) != 0 {
		t.Errorf("composer install reads lockfile — expected no finding, got %d", len(f))
	}
}
