// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
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

func TestGL060_RunDockerSocketIsWarn(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run -v /run/docker.sock:/var/run/docker.sock myimage
`)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn finding for /run/docker.sock, got %+v", f)
	}
}

func TestGL060_MountBindSocketIsWarn(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock myimage
`)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected 1 warn finding for mount form socket bind, got %+v", f)
	}
}

func TestGL060_MountBindEtcIsError(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run --mount type=bind,src=/etc,dst=/x myimage
`)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error finding for mount form /etc bind, got %+v", f)
	}
}

func TestGL060_MountEqualsFormIsError(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run --mount=type=bind,source=/etc,target=/x myimage
`)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Fatalf("expected 1 error finding for equals form mount bind, got %+v", f)
	}
}

func TestGL060_MountVolumeNamedNotFlagged(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run --mount type=volume,source=name myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for named volume mount, got %d", len(f))
	}
}

func TestGL060_MountTmpfsNotFlagged(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker run --mount type=tmpfs,target=/x myimage
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for tmpfs mount, got %d", len(f))
	}
}

func TestGL060_PodmanAndNerdctlRun(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - podman run -v /etc:/etc myimage
    - nerdctl run -v /etc:/etc myimage
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for podman and nerdctl run, got %+v", f)
	}
}

func TestGL060_DockerCreateAndContainerRun(t *testing.T) {
	f := findings060(t, `
test:
  script:
    - docker create -v /etc:/etc myimage
    - docker container run -v /etc:/etc myimage
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for docker create and container run, got %+v", f)
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

// Read-only mounts of world-readable identity files expose nothing; other
// read-only mounts say read, not read/write (#995).
func TestGL060_ReadOnlyMounts(t *testing.T) {
	for _, tc := range []struct {
		line, want string
	}{
		{`docker run --rm -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro example/tool`, ""},
		{`docker run --rm --mount type=bind,source=/etc/passwd,target=/etc/passwd,readonly example/tool`, ""},
		{`docker run --rm -v /etc/passwd:/etc/passwd example/tool`, "read/write"},
		{`docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro example/tool`, "can read host"},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - '"+tc.line+"'\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		f := GL060.Check(doc.Root, "test.yml")
		switch {
		case tc.want == "" && len(f) != 0:
			t.Errorf("%s: got %v, want no finding", tc.line, f)
		case tc.want != "" && (len(f) != 1 || !strings.Contains(f[0].Message, tc.want)):
			t.Errorf("%s: got %v, want one finding saying %q", tc.line, f, tc.want)
		}
	}
}

func TestMountReadOnly(t *testing.T) {
	for spec, want := range map[string]bool{
		"type=bind,source=/etc/passwd,target=/etc/passwd,readonly": true,
		"type=bind,src=/etc,dst=/etc,ro=false":                     false,
		"type=bind,source=/etc,target=/etc":                        false,
	} {
		if got := mountReadOnly(spec); got != want {
			t.Errorf("mountReadOnly(%q) = %v, want %v", spec, got, want)
		}
	}
}
