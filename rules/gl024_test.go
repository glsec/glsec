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

func TestGL024_PipeWithoutPipefail(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - generate-config | tee config.yml
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn, got %s", f[0].Severity)
	}
}

func TestGL024_PipefailSet_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - set -o pipefail
    - generate-config | tee config.yml
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when pipefail is set, got %d", len(f))
	}
}

func TestGL024_PipefailInline_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - set -o pipefail && generate-config | tee config.yml
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when pipefail set inline, got %d", len(f))
	}
}

func TestGL024_SetEuoPipefail_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - set -euo pipefail
    - generate-config | tee config.yml
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for set -euo pipefail, got %d", len(f))
	}
}

func TestGL024_LogicalOr_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - cmd || true
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for || (logical OR), got %d", len(f))
	}
}

func TestGL024_PipeAndLogicalOr(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - generate-config | tee config.yml || true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (real pipe present despite ||), got %d", len(f))
	}
}

func TestGL024_NoPipe_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - go build ./...
    - go test ./...
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for script without pipes, got %d", len(f))
	}
}

func TestGL024_PipefailInBeforeScript_NoFinding(t *testing.T) {
	f := findings024(t, `
build:
  before_script:
    - set -o pipefail
  script:
    - generate-config | tee config.yml
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when pipefail set in before_script, got %d", len(f))
	}
}

func TestGL024_OneFindingPerJob(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - cmd1 | tee out1.txt
    - cmd2 | tee out2.txt
    - cmd3 | tee out3.txt
`)
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 finding per job (at first pipe), got %d", len(f))
	}
}

func TestGL024_MultipleJobs(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - set -o pipefail
    - cmd | tee out.txt

test:
  script:
    - cmd | tee out.txt
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (only test job), got %d", len(f))
	}
}

func TestGL024_LineNumber(t *testing.T) {
	f := findings024(t, `
build:
  script:
    - generate-config | tee config.yml
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL024_WindowsRunner_NoFinding(t *testing.T) {
	cases := map[string]string{
		"job tags": `
win:
  tags: [windows]
  script:
    - Get-ChildItem | Select-Object Name
`,
		"hosted runner tag": `
win:
  tags: [saas-windows-medium-amd64]
  script:
    - Get-ChildItem | Select-Object Name
`,
		"extends string": `
.win:
  tags: [Shared-Windows]
win:
  extends: .win
  script:
    - Get-ChildItem | Select-Object Name
`,
		"extends list, last wins": `
.linux:
  tags: [docker]
.win:
  tags: [windows-1809]
win:
  extends: [.linux, .win]
  script:
    - Get-ChildItem | Select-Object Name
`,
		"nested extends": `
.base:
  tags: [windows]
.mid:
  extends: .base
win:
  extends: .mid
  script:
    - Get-ChildItem | Select-Object Name
`,
		"default tags": `
default:
  tags: [windows]
win:
  script:
    - Get-ChildItem | Select-Object Name
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 0 {
				t.Errorf("expected no finding on a Windows runner, got %d", len(f))
			}
		})
	}
}

func TestGL024_NonWindowsRunner_StillReported(t *testing.T) {
	cases := map[string]string{
		"linux tags": `
build:
  tags: [docker, linux]
  script:
    - generate-config | tee config.yml
`,
		"job tags override windows default": `
default:
  tags: [windows]
build:
  tags: [docker]
  script:
    - generate-config | tee config.yml
`,
		"extends list, linux last": `
.win:
  tags: [windows]
.linux:
  tags: [docker]
build:
  extends: [.win, .linux]
  script:
    - generate-config | tee config.yml
`,
		"word inside another word": `
build:
  tags: [nowindowsrunner]
  script:
    - generate-config | tee config.yml
`,
		"cyclic extends": `
.a:
  extends: .b
.b:
  extends: .a
build:
  extends: .a
  script:
    - generate-config | tee config.yml
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 1 {
				t.Errorf("expected 1 finding, got %d", len(f))
			}
		})
	}
}

func TestGL024_InheritedPipefail_NoFinding(t *testing.T) {
	cases := map[string]string{
		"extends before_script": `
.base:
  before_script:
    - set -o pipefail
build:
  extends: .base
  script:
    - generate-config | tee config.yml
`,
		"nested extends": `
.base:
  before_script:
    - set -euo pipefail
.mid:
  extends: .base
build:
  extends: [.other, .mid]
  script:
    - generate-config | tee config.yml
`,
		"default before_script": `
default:
  before_script:
    - set -o pipefail
build:
  script:
    - generate-config | tee config.yml
`,
		"inherit default list with before_script": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    default: [before_script]
  script:
    - generate-config | tee config.yml
`,
		"inherit without default": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    variables: false
  script:
    - generate-config | tee config.yml
`,
		"inherit default true": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    default: true
  script:
    - generate-config | tee config.yml
`,
		"inherit default of unknown shape": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    default: {before_script: true}
  script:
    - generate-config | tee config.yml
`,
		"non-string extends entry skipped": `
.base:
  before_script:
    - set -o pipefail
build:
  extends: [.base, {bad: entry}]
  script:
    - generate-config | tee config.yml
`,
		"top-level before_script": `
before_script:
  - set -o pipefail
build:
  script:
    - generate-config | tee config.yml
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 0 {
				t.Errorf("expected no finding, got %d", len(f))
			}
		})
	}
}

func TestGL024_InheritedPipefail_NotApplied(t *testing.T) {
	cases := map[string]string{
		"job overrides before_script": `
default:
  before_script:
    - set -o pipefail
build:
  before_script:
    - echo start
  script:
    - generate-config | tee config.yml
`,
		"inherit default false": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    default: false
  script:
    - generate-config | tee config.yml
`,
		"inherit default list without before_script": `
default:
  before_script:
    - set -o pipefail
build:
  inherit:
    default: [image]
  script:
    - generate-config | tee config.yml
`,
		"after_script runs in its own shell": `
.base:
  after_script:
    - set -o pipefail
build:
  extends: .base
  script:
    - generate-config | tee config.yml
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings024(t, src); len(f) != 1 {
				t.Errorf("expected 1 finding, got %d", len(f))
			}
		})
	}
}

// extendsChain returns jobs job0..jobN where each job extends the one before
// and only job0 sets tags.
func extendsChain(n int) string {
	var b strings.Builder
	b.WriteString("job0:\n  tags: [windows]\n  script: [\"a | b\"]\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "job%d:\n  extends: job%d\n  script: [\"a | b\"]\n", i, i-1)
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

func TestGL024_LongExtendsChainIsFast(t *testing.T) {
	src := extendsChain(5000)
	done := make(chan struct{})
	go func() { findings024(t, src); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a 5000-job extends chain did not finish in 5s")
	}
}

func TestGL024_QuotedPipes(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{`sed -i "s|http://old|https://new|g" sources.list`, 0},
		{`perl -pi -e 's|\r||g' file`, 0},
		{`git log --grep "(^Signed-off-by)|(^Merge branch)"`, 0},
		{`ctest -LE "slow|broken"`, 0},
		{`find . -regex '.*\.\(htm\|html\)$'`, 0},
		{`echo "|1|abc" >> ~/.ssh/known_hosts`, 0},
		{`cmd >| out.log`, 0},
		{`a || b`, 0},
		{`cat f | grep x`, 1},
		{`make 2>&1 | tee build.log`, 1},
		{`make |& tee build.log`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - "+strconv.Quote(tc.script)+"\n"), "t.yml")
		if err != nil {
			t.Fatal(err)
		}
		if f := GL024.Check(doc.Root, "t.yml"); len(f) != tc.want {
			t.Errorf("%s: expected %d findings, got %d", tc.script, tc.want, len(f))
		}
	}
}
