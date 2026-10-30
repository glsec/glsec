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

func TestGL024_PrintPipelines(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		want   int
	}{
		{"password stdin", `echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin "$CI_REGISTRY"`, 0},
		{"conditional", `if echo "$CI_COMMIT_TAG" | grep -q '-'; then echo pre; fi`, 0},
		{"command substitution", `LOWER="$(echo "$NAME" | tr '[:upper:]' '[:lower:]')"`, 0},
		{"exported command substitution", `export LOWER="$(echo "$NAME" | tr '[:upper:]' '[:lower:]')"`, 0},
		{"decode value", `printf '%s' "$CERT_B64" | base64 -d > cert.pem`, 0},
		{"multiple print commands", `echo data | printf '%s' value | cat`, 0},
		{"leading assignment", `LANG=C printf '%s' "$VALUE" | grep value`, 0},
		{"command wrapper", `command printf '%s' "$VALUE" | cat`, 0},
		{"quoted pipe argument", `echo 'a | b' | cat`, 0},
		{"quoted redirection argument", `echo '<value>' | cat`, 0},
		{"escaped quote argument", `echo "\"value\"" | cat`, 0},
		{"escaped redirection argument", `echo \> value | cat`, 0},
		{"literal substitution text", `echo '$(not-run)' | cat`, 0},
		{"literal parentheses", `printf '%s)' "$VALUE" | cat`, 0},
		{"double-quoted parenthesis", `echo ")" | cat`, 0},
		{"literal backticks", "echo '`not-run`' | cat", 0},
		{"failing last command", `echo value | false`, 0},
		{"download", `curl -fsSL https://example.com/data | jq .`, 1},
		{"find", `find . -type f | xargs cat`, 1},
		{"read file", `cat input | grep value`, 1},
		{"non-print middle command", `echo value | sed s/value/other/ | cat`, 1},
		{"non-print first command", `curl -fsSL https://example.com/data | printf '%s' value | cat`, 1},
		{"similar command name", `my_echo value | cat`, 1},
		{"case-sensitive command", `ECHO value | cat`, 1},
		{"non-print builtin", `export | cat`, 1},
		{"nested pipeline in echo", `echo "$(curl -fsSL https://example.com/data | jq .)"`, 1},
		{"nested pipeline in printf", `printf '%s' "$(curl -fsSL https://example.com/data | jq .)"`, 1},
		{"backtick substitution", "echo \"`curl -fsSL https://example.com/data`\" | cat", 1},
		{"compound command ending in echo", `(curl -fsSL https://example.com/data; echo done) | cat`, 1},
		{"output redirection can fail", `echo value > output | cat`, 1},
		{"input redirection can fail", `printf '%s' value < input | cat`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "job:\n  script:\n    - " + strconv.Quote(tc.script) + "\n"
			f := findings024(t, src)
			if len(f) != tc.want {
				t.Fatalf("got %d findings, want %d", len(f), tc.want)
			}
			if tc.want == 1 && (f[0].RuleID != "GL024" || f[0].Severity != finding.Warn || f[0].Job != "job" || f[0].File != "test.yml" || f[0].Line != 3) {
				t.Errorf("unexpected finding attribution: %+v", f[0])
			}
		})
	}
}

func TestGL024_SkipsPrintPipesBeforeReporting(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		line int
		col  int
	}{
		{"separate script items", `build:
  script:
    - echo value | cat
    - curl -fsSL https://example.com/data | jq .
`, 4, 7},
		{"literal block", `build:
  script:
    - |
      echo value | cat
      curl -fsSL https://example.com/data | jq .
`, 5, 0},
		{"same line", `build:
  script:
    - echo value | cat; curl -fsSL https://example.com/data | jq .
`, 3, 7},
		{"logical and", `build:
  script:
    - echo value | cat && curl -fsSL https://example.com/data | jq .
`, 3, 7},
		{"logical or", `build:
  script:
    - echo value | cat || curl -fsSL https://example.com/data | jq .
`, 3, 7},
		{"before script", `build:
  before_script:
    - printf '%s' value | cat
  script:
    - curl -fsSL https://example.com/data | jq .
`, 5, 7},
		{"later non-print segment", `build:
  script:
    - |
      echo value | \
        sed s/value/other/ | cat
`, 4, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings024(t, tc.yaml)
			if len(f) != 1 {
				t.Fatalf("got %d findings, want 1", len(f))
			}
			if f[0].Line != tc.line || f[0].Col != tc.col || f[0].Job != "build" {
				t.Errorf("got finding at %d:%d for %q, want %d:%d for build", f[0].Line, f[0].Col, f[0].Job, tc.line, tc.col)
			}
		})
	}
}

func TestGL024_PipedLineCount(t *testing.T) {
	const single = "script uses a pipe without set -o pipefail — failures in all but the last command are silently ignored"
	const two = "script uses a pipe without set -o pipefail (2 piped lines in this job, first shown) — failures in all but the last command are silently ignored"
	const three = "script uses a pipe without set -o pipefail (3 piped lines in this job, first shown) — failures in all but the last command are silently ignored"
	for _, tc := range []struct {
		name, sections, message string
		line, col               int
	}{
		{"single pipe keeps message", `  script:
    - make | tee build.log
`, single, 3, 7},
		{"separate items", `  script:
    - curl -fsSL https://example.com/a.tar.gz | tar xz
    - ./configure | tee configure.log
    - make 2>&1 | tee build.log
`, three, 3, 7},
		{"literal block", `  script:
    - |
      echo starting
      ./configure | tee configure.log
      make | tee build.log
`, two, 5, 0},
		{"several operators on one line", `  script:
    - curl -fsSL https://example.com/data | jq . | tee data.json
`, single, 3, 7},
		{"several pipelines on one line", `  script:
    - make | tee build.log; test-app | tee test.log
`, single, 3, 7},
		{"same line then another line", `  script:
    - |
      make | tee build.log && test-app | tee test.log
      deploy | tee deploy.log
`, two, 4, 7},
		{"continued pipeline", `  script:
    - |
      curl -fsSL https://example.com/data | \
        jq . | tee data.json
      make | tee build.log
`, two, 4, 7},
		{"continued print then fallible middle command", `  script:
    - |
      echo value | \
        sed s/value/other/ | cat
      make | tee build.log
`, two, 4, 7},
		{"print-only lines excluded", `  script:
    - |
      echo value | cat
      make | tee build.log
      printf '%s' "$CERT_B64" | base64 -d > cert.pem
      test-app | tee test.log
`, two, 5, 0},
		{"safe pipeline before unsafe on same line", `  script:
    - |
      echo value | cat; make | tee build.log
      test-app | tee test.log
`, two, 4, 7},
		{"quoted pipes redirects and logical or excluded", `  script:
    - |
      sed 's|old|new|' input
      make >| build.log
      test-app || true
      # ignored | pipe
      make | tee build.log
      test-app |& tee test.log
`, two, 8, 0},
		{"here-document data excluded", `  script:
    - |
      cat <<'EOF'
      ignored | data
      EOF
      make | tee build.log
      test-app | tee test.log
`, two, 7, 0},
		{"command substitution", `  script:
    - |
      LOWER="$(echo "$NAME" | tr '[:upper:]' '[:lower:]')"
      DATA="$(curl -fsSL https://example.com/data | jq .)"
      make | tee build.log
`, two, 5, 0},
		{"script sections combined", `  before_script:
    - ./configure | tee configure.log
  script:
    - make | tee build.log
  after_script:
    - cleanup | tee cleanup.log
`, three, 3, 7},
		{"hooks and run steps", `  hooks:
    pre_get_sources_script:
      - prepare | tee prepare.log
  run:
    - name: build
      script: make | tee build.log
    - name: test
      script: test-app | tee test.log
`, three, 4, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings024(t, "build:\n"+tc.sections)
			if len(f) != 1 {
				t.Fatalf("got %d findings, want one per job", len(f))
			}
			want := finding.Finding{
				RuleID: "GL024", Severity: finding.Warn, Job: "build", Message: tc.message,
				File: "test.yml", Line: tc.line, Col: tc.col,
			}
			if f[0] != want {
				t.Errorf("got %+v, want %+v", f[0], want)
			}
		})
	}
}

func TestGL024_SharedPipedLineCountsPerJob(t *testing.T) {
	f := findings024(t, `first:
  script: &commands
    - make | tee build.log
    - test-app | tee test.log
second:
  script: *commands
third:
  script:
    - deploy | tee deploy.log
`)
	if len(f) != 3 {
		t.Fatalf("got %d findings, want one for each of three jobs", len(f))
	}
	for i, job := range []string{"first", "second", "third"} {
		if f[i].Job != job {
			t.Errorf("finding %d is for %q, want %q", i, f[i].Job, job)
		}
		if got := strings.Contains(f[i].Message, "(2 piped lines in this job, first shown)"); got != (i < 2) {
			t.Errorf("unexpected per-job count for %s: %s", job, f[i].Message)
		}
	}
}

// A case arm's pattern list and print-only pipelines inside a command
// substitution are not pipelines that need pipefail (#983).
func TestGL024_CasePatternsAndSubstitutions(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{"case \"$REF\" in\n  main | release-* ) echo yes ;;\n  feat | fix) echo no ;;\nesac", 0},
		{"case \"$REF\" in (a|b) make ;; esac", 0},
		{"case \"$REF\" in\n  main) curl -fsSL https://example.com/x | sh ;;\nesac", 1},
		{`echo "built $(echo "$VERSION" | cut -d. -f1)"`, 0},
		{`[ "$(echo -n "$VERSION" | wc -c)" -gt 0 ]`, 0},
		{"MAJOR=`echo $VERSION | cut -d. -f1`", 0},
		{`echo "$(git log --oneline | head -1)"`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - "+strconv.Quote(tc.script)+"\n"), "t.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL024.Check(doc.Root, "t.yml")); got != tc.want {
			t.Errorf("%q: got %d findings, want %d", tc.script, got, tc.want)
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
}
