// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
	"github.com/glsec/glsec/rules"
)

// largePipeline builds a pipeline far bigger than real ones, with every
// construct that has caused slow scans before: extends: and !reference
// chains, anchors and merge keys, long script blocks, one very long line and
// many rules: entries (#838).
// jobs sets the number of jobs, lineRepeat the length of the long line.
func largePipeline(jobs, lineRepeat int) string {
	var b strings.Builder
	b.WriteString("stages: [build, test, deploy]\n\nvariables:\n")
	for i := range 50 {
		fmt.Fprintf(&b, "  VAR_%d: value-%d\n", i, i)
	}
	b.WriteString(`
workflow:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

.base: &base
  image: alpine:3.20.3
  before_script:
    - set -eo pipefail
    - apk add --no-cache curl

.t0:
  tags: [docker]
`)
	for i := 1; i < 10; i++ {
		fmt.Fprintf(&b, ".t%d:\n  extends: .t%d\n  variables:\n    LEVEL_%d: \"%d\"\n", i, i-1, i, i)
	}
	b.WriteString(".ref0:\n  script:\n    - echo ref0\n")
	for i := 1; i < 10; i++ {
		fmt.Fprintf(&b, ".ref%d:\n  script:\n    - !reference [.ref%d, script]\n    - echo ref%d\n", i, i-1, i)
	}
	for i := range jobs {
		fmt.Fprintf(&b, "\njob_%d:\n  <<: *base\n  extends: .t9\n  stage: test\n", i)
		if i%100 == 0 {
			b.WriteString("  rules:\n")
			for r := range 50 {
				fmt.Fprintf(&b, "    - if: $CI_COMMIT_BRANCH == \"branch-%d\"\n      changes: [\"dir%d/**/*\"]\n", r, r)
			}
		}
		b.WriteString("  script:\n    - !reference [.ref9, script]\n")
		if i%200 == 0 {
			b.WriteString("    - |\n")
			for l := range 500 {
				fmt.Fprintf(&b, "      curl -fsSL https://example.com/%d | grep -v x | tee out-%d.log\n", l, l)
			}
		}
		fmt.Fprintf(&b, "    - ./run.sh %d\n", i)
	}
	b.WriteString("\nlong_line:\n  script:\n    - echo " + strings.Repeat("a | b ", lineRepeat) + "\n")
	return b.String()
}

// raceEnabled reports whether the tests run with -race, which makes the
// large-pipeline tests take minutes. It reads the build settings rather than
// a build tag, which gobco ignores when it copies the package.
func raceEnabled() bool {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "-race" {
				return s.Value == "true"
			}
		}
	}
	return false
}

func parsePipeline(t *testing.T, src string) *parser.Document {
	t.Helper()
	doc, err := parser.Parse([]byte(src), ".gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// ruleTimes returns how long each rule takes on doc, the fastest of three runs.
func ruleTimes(doc *parser.Document) map[string]time.Duration {
	times := map[string]time.Duration{}
	for range 3 {
		for _, r := range rules.All() {
			d := ruleTime(r, doc)
			if old, ok := times[r.ID()]; !ok || d < old {
				times[r.ID()] = d
			}
		}
	}
	return times
}

func ruleTime(r rule.Rule, doc *parser.Document) time.Duration {
	start := time.Now()
	rules.Check(r, doc, ".gitlab-ci.yml")
	return time.Since(start)
}

// remeasure times r on both pipelines again, fastest of runs runs each, with
// a garbage collection before every run so a pause left over from an earlier
// rule doesn't land in this one.
func remeasure(r rule.Rule, small, large *parser.Document, runs int) (s, l time.Duration) {
	best := func(doc *parser.Document) time.Duration {
		var fastest time.Duration
		for i := range runs {
			runtime.GC()
			if d := ruleTime(r, doc); i == 0 || d < fastest {
				fastest = d
			}
		}
		return fastest
	}
	return best(small), best(large)
}

// TestRulesScaleLinearly runs every rule on a pipeline and on one four times
// its size, and fails when a rule takes more than ten times as long: linear
// work grows about 4x, quadratic work 16x. A ratio doesn't depend on how fast
// the runner is or on -race, so it catches a quadratic rule (GL089 was one,
// #838) without a flaky time budget. A ratio of a few milliseconds is noise on
// a busy machine (#868), so a rule is judged only when it takes at least
// minTime on both pipelines, and one over the limit is measured again before
// it fails.
func TestRulesScaleLinearly(t *testing.T) {
	if testing.Short() || raceEnabled() {
		t.Skip("large pipelines; CI runs this without -race")
	}
	const (
		maxRatio = 10
		minTime  = 5 * time.Millisecond
	)
	cases := []struct {
		name         string
		small, large string
	}{
		{"jobs", largePipeline(500, 0), largePipeline(2000, 0)},
		{"line length", largePipeline(1, 2000), largePipeline(1, 8000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			smallDoc, largeDoc := parsePipeline(t, c.small), parsePipeline(t, c.large)
			small, large := ruleTimes(smallDoc), ruleTimes(largeDoc)
			for _, r := range rules.All() {
				s, l := small[r.ID()], large[r.ID()]
				if s < minTime || float64(l)/float64(s) <= maxRatio {
					continue
				}
				s, l = remeasure(r, smallDoc, largeDoc, 5)
				if s < minTime {
					continue
				}
				if ratio := float64(l) / float64(s); ratio > maxRatio {
					t.Errorf("%s: 4x the input took %.1fx as long (%s vs %s), want at most %dx", r.ID(), ratio, l.Round(time.Millisecond), s.Round(time.Millisecond), maxRatio)
				}
			}
		})
	}
}

// TestLargePipelineAllFormats checks that every output format handles a large
// pipeline.
func TestLargePipelineAllFormats(t *testing.T) {
	if testing.Short() || raceEnabled() {
		t.Skip("large pipelines; CI runs this without -race")
	}
	files := map[string]string{".gitlab-ci.yml": largePipeline(100, 1000)}
	for _, format := range []string{"text", "table", "json", "sarif", "codeclimate", "junit"} {
		if code, stdout, stderr := runCLI(t, files, "--no-cache", "--format", format, ".gitlab-ci.yml"); code == 2 || !strings.Contains(stdout, "GL022") {
			t.Errorf("--format %s: exit %d, no GL022 finding: %s", format, code, stderr)
		}
	}
}

// TestWriteBenchmarkInput writes the pipeline the benchmark history scans to
// the file GLSEC_BENCH_INPUT names (#875). The history workflow measures every
// commit and old release on one stored copy, so a change to largePipeline
// doesn't shift the series; regenerate it only together with a new input
// version on the benchmarks branch.
func TestWriteBenchmarkInput(t *testing.T) {
	path := os.Getenv("GLSEC_BENCH_INPUT")
	if path == "" {
		t.Skip("set GLSEC_BENCH_INPUT to write the benchmark input")
	}
	if err := os.WriteFile(path, []byte(largePipeline(2000, 0)), 0o600); err != nil { //nolint:gosec // G703: the developer names the output file
		t.Fatal(err)
	}
}

func BenchmarkParse(b *testing.B) {
	src := []byte(largePipeline(2000, 20000))
	b.SetBytes(int64(len(src)))
	for b.Loop() {
		if _, err := parser.Parse(src, ".gitlab-ci.yml"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRules(b *testing.B) {
	doc, err := parser.Parse([]byte(largePipeline(2000, 20000)), ".gitlab-ci.yml")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		for _, r := range rules.All() {
			rules.Check(r, doc, ".gitlab-ci.yml")
		}
	}
}

func BenchmarkRun(b *testing.B) {
	dir := b.TempDir()
	b.Chdir(dir)
	if err := os.WriteFile(".gitlab-ci.yml", []byte(largePipeline(2000, 20000)), 0o600); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		run([]string{"--no-cache", "--format", "json", ".gitlab-ci.yml"}, io.Discard, io.Discard)
	}
}
