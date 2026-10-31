// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings024(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL024.Check(doc.Root, "test.yml")
}

func count024(t *testing.T, script string) int {
	t.Helper()
	return len(findings024(t, "job:\n  script:\n    - "+strconv.Quote(script)+"\n"))
}

func TestGL024_ChildShellPipe(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - docker run --rm alpine:3.20 sh -c "generate-config | tee config.yml"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info, got %s", f[0].Severity)
	}
	if !strings.Contains(f[0].Message, "`sh -c`") || !strings.Contains(f[0].Message, "runner's pipefail") {
		t.Errorf("message: %s", f[0].Message)
	}
	if f[0].Line != 4 || f[0].Col != 7 {
		t.Errorf("location %d:%d, want 4:7", f[0].Line, f[0].Col)
	}
}

// The runner starts job scripts with set -o pipefail, so pipes in the job's
// own shell are not reported (#1047).
func TestGL024_JobShellPipes_NoFinding(t *testing.T) {
	for _, s := range []string{
		"generate-config | tee config.yml",
		"curl -fsSL https://example.com/x | tar xz",
		"set +o pipefail\nyes | sdkmanager --licenses",
		`X="$(git log --oneline | head -1)"`,
		"ssh host \"cmd\" | tee log",
	} {
		if n := count024(t, s); n != 0 {
			t.Errorf("%q: got %d findings, want 0", s, n)
		}
	}
}

func TestGL024_ChildShells(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{`sh -c "a | b"`, 1},
		{`bash -c 'a | b'`, 1},
		{`/bin/sh -ec "a | b; c"`, 1},
		{`sudo -u app bash -c "a | b"`, 1},
		{`kubectl exec pod -- sh -c "a | b"`, 1},
		{`ssh -i key -p 22 deploy@host "journalctl -u app | tail"`, 1},
		{`ssh -o StrictHostKeyChecking=no host 'a | b'`, 1},
		{`sh -c "a | b && c"`, 1},
		{`sh -c "set -e; a | b; c"`, 1},
		{`sh -c "set -o errexit; a | b; c"`, 1},
		// pipefail inside the script or on the shell's command line
		{`sh -c "set -o pipefail; a | b"`, 0},
		{`bash -euo pipefail -c "a | b"`, 0},
		{`bash -o pipefail -c "a | b"`, 0},
		// without errexit only the last command's status counts
		{`sh -c "a | b; c"`, 0},
		// status tested or handled
		{`sh -c "a | b || true"`, 0},
		{`sh -c "if a | grep -q x; then c; fi"`, 0},
		{`timeout 60 sh -c 'until curl -s x | grep -q y; do sleep 1; done'`, 0},
		{`bash -c "compgen -c x | grep -q x && exit || exit 1"`, 0},
		{`sh -c "a | grep x > /dev/null"`, 0},
		// print-only pipelines, substitutions, no pipe
		{`sh -c 'echo "$P" | docker login --password-stdin'`, 0},
		{`sh -c 'cp "$0" "out/$(basename "$0" | sed s/a/b/)"' {} \;`, 0},
		{`sh -c "a || b"`, 0},
		{`sh -c "sed 's|a|b|' f"`, 0},
		{`sh -c "a | grep --quiet x"`, 0},
		{`ssh host uptime`, 0},
		{`ssh -p 22`, 0},
		{`sh -c`, 0},
		{`echo sh -c "a | b"`, 0},
		{"sh -c \"case $X in a|b) c ;; esac\"", 0},
	} {
		if n := count024(t, tc.script); n != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.script, n, tc.want)
		}
	}
}

func TestGL024_OneFindingPerJob(t *testing.T) {
	f := findings024(t, `
build:
  before_script:
    - sh -c "a | b"
  script:
    - make
    - bash -c "c | d"
  after_script:
    - ssh host "e | f"
deploy:
  script:
    - sh -c "g | h"
`)
	if len(f) != 2 {
		t.Fatalf("got %d findings, want one per job", len(f))
	}
	if f[0].Job != "build" || !strings.Contains(f[0].Message, "(3 piped lines in this job, first shown)") || f[0].Line != 4 {
		t.Errorf("build: %+v", f[0])
	}
	if f[1].Job != "deploy" || strings.Contains(f[1].Message, "piped lines") {
		t.Errorf("deploy: %+v", f[1])
	}
}

func TestGL024_LineInBlock(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - |
      make
      sh -c "a | b"
`)
	if len(f) != 1 || f[0].Line != 6 || f[0].Col != 0 {
		t.Fatalf("got %+v, want one finding on line 6 without a column", f)
	}
}

func TestGL024_SharedLineCountsPerJob(t *testing.T) {
	f := findings024(t, `first:
  script: &commands
    - sh -c "make | tee build.log"
second:
  script: *commands
`)
	if len(f) != 2 || f[0].Job != "first" || f[1].Job != "second" {
		t.Fatalf("got %+v, want one finding for each job", f)
	}
}

func TestGL024_WindowsRunner_NoFinding(t *testing.T) {
	cases := map[string]string{
		"job tags": `
win:
  tags: [windows]
  script:
    - sh -c "a | b"
`,
		"extends list, last wins": `
.linux:
  tags: [docker]
.win:
  tags: [windows-1809]
win:
  extends: [.linux, .win]
  script:
    - sh -c "a | b"
`,
		"default tags": `
default:
  tags: [windows]
win:
  script:
    - sh -c "a | b"
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 0 {
				t.Errorf("expected no finding on a Windows runner, got %d", len(f))
			}
		})
	}
	if f := findings024(t, "build:\n  tags: [docker, linux]\n  script:\n    - sh -c \"a | b\"\n"); len(f) != 1 {
		t.Errorf("linux tags: got %d findings, want 1", len(f))
	}
}

func extendsChain(n int) string {
	var b strings.Builder
	b.WriteString("job0:\n  tags: [windows]\n  script: [\"sh -c 'a | b'\"]\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "job%d:\n  extends: job%d\n  script: [\"sh -c 'a | b'\"]\n", i, i-1)
	}
	return b.String()
}

func TestGL024_ExtendsDepthLimit(t *testing.T) {
	// job11 is eleven levels below job0 and inherits its Windows tags; job12
	// is past GitLab's limit.
	var jobs []string
	for _, f := range findings024(t, extendsChain(12)) {
		jobs = append(jobs, f.Job)
	}
	if len(jobs) != 1 || jobs[0] != "job12" {
		t.Errorf("got findings for %v, want only job12", jobs)
	}
}

// It takes well under 2 s, also with -race. The limit is generous because
// CI runs packages in parallel on small runners; a walk that grows
// exponentially with the chain would not finish at all.
func TestGL024_LongExtendsChainIsFast(t *testing.T) {
	src := extendsChain(5000)
	done := make(chan struct{})
	go func() { findings024(t, src); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("a 5000-job extends chain did not finish in 60s")
	}
}

func TestIsSimplePrintCommand(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
	}{
		{`echo "$CI_REGISTRY_PASSWORD"`, true},
		{`printf '%s' "$CERT_B64"`, true},
		{`LOWER="$(echo "$NAME"`, true},
		{`echo "|1|abc"`, true},
		{`echo "$(curl x)"`, false},
		{`echo x > f`, false},
		{`cat f`, false},
	} {
		if got := isSimplePrintCommand(tc.text); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.text, got, tc.want)
		}
	}
}

func TestNeedsPipefail(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   bool
	}{
		{`echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin "$CI_REGISTRY"`, false},
		{`if echo "$CI_COMMIT_TAG" | grep -q '-'; then echo pre; fi`, false},
		{`LOWER="$(echo "$NAME" | tr '[:upper:]' '[:lower:]')"`, false},
		{`printf '%s' "$CERT_B64" | base64 -d > cert.pem`, false},
		{`echo data | printf '%s' value | cat`, false},
		{`LANG=C printf '%s' "$VALUE" | grep value`, false},
		{`command printf '%s' "$VALUE" | cat`, false},
		{`echo 'a | b' | cat`, false},
		{`echo '<value>' | cat`, false},
		{`echo "\"value\"" | cat`, false},
		{`echo \> value | cat`, false},
		{`echo '$(not-run)' | cat`, false},
		{`printf '%s)' "$VALUE" | cat`, false},
		{`echo ")" | cat`, false},
		{"echo '`not-run`' | cat", false},
		{`echo value | false`, false},
		{`echo "$(curl -fsSL https://example.com/data | jq .)"`, false},
		{`curl -fsSL https://example.com/data | jq .`, true},
		{`find . -type f | xargs cat`, true},
		{`cat input | grep value`, true},
		{`echo value | sed s/value/other/ | cat`, true},
		{`curl -fsSL https://example.com/data | printf '%s' value | cat`, true},
		{`my_echo value | cat`, true},
		{`ECHO value | cat`, true},
		{`export | cat`, true},
		{"echo \"`curl -fsSL https://example.com/data`\" | cat", true},
		{`(curl -fsSL https://example.com/data; echo done) | cat`, true},
		{`echo value > output | cat`, true},
		{`printf '%s' value < input | cat`, true},
		{"case \"$REF\" in\n  main | release-* ) echo yes ;;\nesac", false},
		{"case \"$REF\" in\n  main) curl -fsSL https://example.com/x | sh ;;\nesac", true},
	} {
		if got := needsPipefail(tc.script, true); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.script, got, tc.want)
		}
	}
}

// Escapes and esac after an arm's body end case pattern masking (#983).
func TestMaskCasePatterns_EscapeAndEsac(t *testing.T) {
	in := "case $X in a\\|b) echo hi ;; esac; curl x | sh"
	got := maskCasePatterns(in)
	if !strings.Contains(got, "curl x | sh") {
		t.Errorf("pipe after esac was masked: %q", got)
	}
	in = "case $X in a) echo hi esac; curl x | sh"
	if got := maskCasePatterns(in); !strings.Contains(got, "curl x | sh") {
		t.Errorf("pipe after esac in a body was masked: %q", got)
	}
	if got := maskCasePatterns("case \"$REF\" in (a|b) make ;; esac"); strings.Contains(got, "|") {
		t.Errorf("case pattern not masked: %q", got)
	}
}
