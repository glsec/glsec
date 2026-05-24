package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings063(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL063.Check(doc.Root, "test.yml")
}

func TestGL063_Chmod777(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod 777 deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn || f[0].RuleID != "GL063" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}

func TestGL063_Recursive777(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod -R 777 /app
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for chmod -R 777, got %d", len(f))
	}
}

func TestGL063_Octal666(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod 666 data.txt
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 666, got %d", len(f))
	}
}

func TestGL063_Octal1777Sticky(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod 1777 /scratch
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for 1777, got %d", len(f))
	}
}

func TestGL063_SymbolicAllWrite(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod a+w secret.key
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a+w, got %d", len(f))
	}
}

func TestGL063_SymbolicOthersWrite(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod o+w deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for o+w, got %d", len(f))
	}
}

func TestGL063_SymbolicARWX(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod a+rwx /workspace
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a+rwx, got %d", len(f))
	}
}

func TestGL063_ExecuteOnlyNotFlagged(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod +x deploy.sh
    - chmod 755 build.sh
    - chmod u+x run.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for +x/755/u+x, got %d", len(f))
	}
}

func TestGL063_RestrictiveOctalNotFlagged(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod 644 config.yml
    - chmod 600 id_rsa
    - chmod 700 bin
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for 644/600/700, got %d", len(f))
	}
}

func TestGL063_GroupWriteNotFlagged(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod g+w shared
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for g+w (group, not others), got %d", len(f))
	}
}

func TestGL063_UnrelatedOctalOnLineNotFlagged(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - chmod +x app && ./app --port 7777
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings (7777 is not the chmod mode), got %d", len(f))
	}
}

func TestGL063_CommentNotFlagged(t *testing.T) {
	f := findings063(t, `
build:
  script:
    - "# chmod 777 would be bad"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}
