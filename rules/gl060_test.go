package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings060(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL060.Check(doc.Root, "test.yml")
}

func TestGL060_RootMountIsError(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run -v /:/host -it myimage chroot /host
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error || f[0].RuleID != "GL060" {
		t.Errorf("expected error severity for / mount, got %+v", f[0])
	}
}

func TestGL060_EtcMountIsError(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run -v /etc:/etc myimage
`)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error finding for /etc, got %+v", f)
	}
}

func TestGL060_VolumeLongFlagAndSubpath(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run --volume /root/.ssh:/keys myimage
`)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error finding for /root subpath, got %+v", f)
	}
}

func TestGL060_VarRunIsWarn(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run -v /var/run:/var/run myimage
`)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn finding for /var/run, got %+v", f)
	}
}

func TestGL060_ProjectDirNotFlagged(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run -v $CI_PROJECT_DIR:/app myimage ./test.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for project dir mount, got %d", len(f))
	}
}

func TestGL060_NamedVolumeNotFlagged(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run -v cache-vol:/cache myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for named volume, got %d", len(f))
	}
}

func TestGL060_NonSensitiveAbsolutePathNotFlagged(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run -v /tmp/build:/build myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for /tmp/build, got %d", len(f))
	}
}

func TestGL060_CommentNotFlagged(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - "# docker run -v /etc:/etc would be dangerous"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for commented line, got %d", len(f))
	}
}
