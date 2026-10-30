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

func findings050(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL050.Check(doc.Root, "test.yml")
}

func TestGL050_SudoAptGet(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - sudo apt-get install -y nodejs
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL050_SudoMakeInstall(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - sudo make install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sudo make install, got %d", len(f))
	}
}

func TestGL050_NoSudoNoFinding(t *testing.T) {
	f := findings050(t, `
build:
  image: node:20.11.1
  script:
    - make install
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without sudo, got %d", len(f))
	}
}

func TestGL050_SubstringNoFinding(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - echo "pseudocode example"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for sudo as substring, got %d", len(f))
	}
}

func TestGL050_ShellCommentNoFinding(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - "# sudo apt-get install nodejs"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for sudo in shell comment, got %d", len(f))
	}
}

func TestGL050_SudoInBeforeScript(t *testing.T) {
	f := findings050(t, `
build:
  before_script:
    - sudo apt-get update
  script:
    - make build
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sudo in before_script, got %d", len(f))
	}
}

func TestGL050_SudoInAfterScript(t *testing.T) {
	f := findings050(t, `
build:
  script:
    - make build
  after_script:
    - sudo rm -rf /tmp/build
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sudo in after_script, got %d", len(f))
	}
}

func TestGL050_GlobalBeforeScript(t *testing.T) {
	f := findings050(t, `
before_script:
  - sudo apt-get update

build:
  script:
    - make build
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sudo in global before_script, got %d", len(f))
	}
}

func TestGL050_JobNameInFinding(t *testing.T) {
	f := findings050(t, `
build-app:
  script:
    - sudo apt-get install -y build-essential
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Job != "build-app" {
		t.Errorf("expected job 'build-app', got %q", f[0].Job)
	}
}

func TestGL050_MultipleSudoLines(t *testing.T) {
	f := findings050(t, `
setup:
  script:
    - sudo apt-get update
    - sudo apt-get install -y nodejs
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for two sudo lines, got %d", len(f))
	}
}

func TestGL050_NotTheCommand(t *testing.T) {
	for _, script := range []string{
		"apt-get install -y jq curl sudo make",
		"pacman -Syu --noconfirm sudo fakeroot",
		`echo "run sudo make install yourself"`,
		"cat > help.html <<EOF\n<p>Then: <code>sudo pacman -Sy tool</code></p>\nEOF",
	} {
		f := findings050(t, "job:\n  script:\n    - |\n"+indentBlock(script)+"\n")
		if len(f) != 0 {
			t.Errorf("%q: expected no finding, got %d", script, len(f))
		}
	}
}

func TestGL050_SudoLaterInBlock(t *testing.T) {
	f := findings050(t, `
job:
  script:
    - |
      apt-get update
      cd build && sudo make install
`)
	if len(f) != 1 || f[0].Line != 6 {
		t.Fatalf("expected one finding on line 6, got %v", f)
	}
}

func indentBlock(s string) string {
	return "      " + strings.ReplaceAll(s, "\n", "\n      ")
}

func TestGL050_SudoInSubstitution(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{"test $(sudo pvesh get /nodes) = ok", 1},
		{"export VMID=$(sudo qm list | head -1)", 1},
		{"echo `sudo id -u`", 1},
		{"echo '$(sudo id)'", 0},
	} {
		if f := findings050(t, "job:\n  script:\n    - "+strconv.Quote(tc.script)+"\n"); len(f) != tc.want {
			t.Errorf("%s: expected %d, got %d", tc.script, tc.want, len(f))
		}
	}
}

// sudo -u with a user other than root drops privileges (#994).
func TestGL050_SudoAsAnotherUser(t *testing.T) {
	for line, want := range map[string]int{
		"sudo -u nobody makepkg -c":     0,
		"sudo --user=builder make":      0,
		"sudo -E -u mysql mariadbd":     0,
		"sudo -Hu postgres psql -c 'x'": 0,
		"sudo -u root make install":     1,
		"sudo make install":             1,
		"sudo -E make install":          1,
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - \""+line+"\"\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL050.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("%s: got %d findings, want %d", line, got, want)
		}
	}
}

func TestSudoDropsPrivileges_Forms(t *testing.T) {
	for args, want := range map[string]bool{
		"-unobody make":  true,
		"-uroot make":    false,
		"-E":             false,
		"-Hu":            false,
		"--user=builder": true,
	} {
		if got := sudoDropsPrivileges(strings.Fields(args)); got != want {
			t.Errorf("sudoDropsPrivileges(%q) = %v, want %v", args, got, want)
		}
	}
}
