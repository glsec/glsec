// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package shellcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

// The test binary doubles as a fake shellcheck: when GLSEC_FAKE_SHELLCHECK is
// set it records its arguments and the script it was given, prints
// FAKE_SC_OUTPUT and exits with FAKE_SC_EXIT. Re-running the test binary works
// the same on Linux, macOS and Windows, unlike a shell script.
func TestMain(m *testing.M) {
	if os.Getenv("GLSEC_FAKE_SHELLCHECK") == "1" {
		os.Exit(fakeShellcheck())
	}
	os.Exit(m.Run())
}

type fakeCall struct {
	Args   []string `json:"args"`
	Script string   `json:"script"`
}

func fakeShellcheck() int {
	call := fakeCall{Args: os.Args[1:]}
	if n := len(os.Args); n > 1 {
		if data, err := os.ReadFile(os.Args[n-1]); err == nil { //nolint:gosec // G304/G703: the fake reads the temp script glsec passed it
			call.Script = string(data)
		}
	}
	if path := os.Getenv("FAKE_SC_RECORD"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: record file in the test's temp dir
		if err == nil {
			_ = json.NewEncoder(f).Encode(call)
			_ = f.Close()
		}
	}
	if ms, _ := strconv.Atoi(os.Getenv("FAKE_SC_SLEEP_MS")); ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
	_, _ = io.WriteString(os.Stderr, os.Getenv("FAKE_SC_STDERR"))
	_, _ = io.WriteString(os.Stdout, os.Getenv("FAKE_SC_OUTPUT"))
	code, _ := strconv.Atoi(os.Getenv("FAKE_SC_EXIT"))
	return code
}

// useFake makes the next Run calls hit the fake and returns the file its calls
// are recorded in.
func useFake(t *testing.T, output string, exit int) string {
	t.Helper()
	record := filepath.Join(t.TempDir(), "calls.jsonl")
	t.Setenv("GLSEC_FAKE_SHELLCHECK", "1")
	t.Setenv("FAKE_SC_RECORD", record)
	t.Setenv("FAKE_SC_OUTPUT", output)
	t.Setenv("FAKE_SC_EXIT", strconv.Itoa(exit))
	return record
}

// mustRun is Run for the cases that must not fail.
func mustRun(t *testing.T, doc *yaml.Node, bin string) []finding.Finding {
	t.Helper()
	got, err := Run(doc, "ci.yml", bin)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func readCalls(t *testing.T, path string) []fakeCall {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: record file in the test's temp dir
	if err != nil {
		t.Fatalf("the fake shellcheck was never called: %v", err)
	}
	var calls []fakeCall
	dec := json.NewDecoder(bytes.NewReader(data))
	for dec.More() {
		var c fakeCall
		if err := dec.Decode(&c); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, c)
	}
	return calls
}

func parseDoc(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return &root
}

const oneJob = `job:
  script:
    - echo start
    - echo $UNQUOTED
`

const sc2086 = `{"comments":[{"line":2,"column":6,"level":"warning","code":2086,"message":"Double quote to prevent globbing."}]}`

func TestRun_MissingBinarySkips(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-shellcheck")
	if got := mustRun(t, parseDoc(t, oneJob), missing); got != nil {
		t.Fatalf("a missing binary should skip ShellCheck, got %v", got)
	}
}

func TestRun_InvocationAndMapping(t *testing.T) {
	record := useFake(t, sc2086, 1) // exit 1 = ShellCheck found something
	got := mustRun(t, parseDoc(t, oneJob), os.Args[0])

	want := []finding.Finding{{
		RuleID: "SC2086", Severity: finding.Warn, Job: "job",
		Message: "Double quote to prevent globbing.", File: "ci.yml", Line: 4, Col: 6,
	}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("findings = %+v, want %+v", got, want)
	}

	calls := readCalls(t, record)
	if len(calls) != 1 {
		t.Fatalf("expected one shellcheck call, got %d", len(calls))
	}
	c := calls[0]
	// Arguments go as a list, the script as a file: nothing from the pipeline
	// reaches the command line, and no shell is involved.
	if len(c.Args) != 4 || c.Args[0] != "--format=json1" || c.Args[1] != "--shell=bash" || c.Args[2] != "--norc" {
		t.Fatalf("unexpected arguments %q", c.Args)
	}
	if c.Script != "echo start\necho $UNQUOTED\n" {
		t.Errorf("script file content = %q", c.Script)
	}
	if _, err := os.Stat(c.Args[3]); !os.IsNotExist(err) {
		t.Errorf("temp script %s was not removed (stat err %v)", c.Args[3], err)
	}
}

func TestRun_ScriptBlocks(t *testing.T) {
	src := `before_script:
  - echo global
default:
  before_script:
    - echo default
  hooks:
    pre_get_sources_script:
      - echo hook
build:
  script:
    - make
  after_script:
    - echo after
steps-job:
  run:
    - name: one
      script: echo step
    - name: remote
      step: gitlab.com/some/step@v1
`
	// The fake reports line 1 of every block, so each block yields one finding.
	useFake(t, `{"comments":[{"line":1,"column":1,"level":"info","code":1000,"message":"m"}]}`, 0)
	got := mustRun(t, parseDoc(t, src), os.Args[0])

	var jobs []string
	for _, f := range got {
		jobs = append(jobs, f.Job+":"+strconv.Itoa(f.Line))
		if f.Severity != finding.Info {
			t.Errorf("level info should map to Info, got %v", f.Severity)
		}
	}
	sort.Strings(jobs)
	want := []string{
		"before_script:2",
		"build:11",
		"build:13",
		"default.before_script:5",
		"default.hooks:pre_get_sources_script:8",
		"steps-job:17",
	}
	if len(jobs) != len(want) {
		t.Fatalf("blocks = %v, want %v", jobs, want)
	}
	for i := range want {
		if jobs[i] != want[i] {
			t.Fatalf("blocks = %v, want %v", jobs, want)
		}
	}
}

func TestRun_OutputWithoutFindings(t *testing.T) {
	tests := []struct {
		name   string
		output string
		exit   int
	}{
		{"no output", "", 0},
		{"comment outside the block", `{"comments":[{"line":9,"column":1,"level":"error","code":1,"message":"m"}]}`, 1},
		{"comment on line 0", `{"comments":[{"line":0,"column":1,"level":"error","code":1,"message":"m"}]}`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFake(t, tt.output, tt.exit)
			if got := mustRun(t, parseDoc(t, oneJob), os.Args[0]); len(got) != 0 {
				t.Fatalf("expected no findings, got %+v", got)
			}
		})
	}
}

// A ShellCheck that fails is an error, not a warning (#907): the message
// names the job and carries ShellCheck's stderr.
func TestRun_FailingShellcheckIsAnError(t *testing.T) {
	tests := []struct {
		name, output, stderr string
		exit                 int
		want                 string
	}{
		{"crash exit code", sc2086, "boom: cannot read rc\n", 3, `shellcheck: job "job": exit status 3: boom: cannot read rc`},
		{"invalid JSON", "not json", "", 1, `shellcheck: job "job": parse output:`},
		{"invalid JSON with stderr", "not json", "warning: old version", 1, "warning: old version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFake(t, tt.output, tt.exit)
			t.Setenv("FAKE_SC_STDERR", tt.stderr)
			got, err := Run(parseDoc(t, oneJob), "ci.yml", os.Args[0])
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
			if got != nil {
				t.Errorf("findings = %v, want none on an error", got)
			}
		})
	}
}

func TestRun_Timeout(t *testing.T) {
	old := Timeout
	Timeout = 200 * time.Millisecond
	t.Cleanup(func() { Timeout = old })
	useFake(t, sc2086, 1)
	t.Setenv("FAKE_SC_SLEEP_MS", "5000")
	start := time.Now()
	_, err := Run(parseDoc(t, oneJob), "ci.yml", os.Args[0])
	if err == nil || !strings.Contains(err.Error(), `job "job": did not finish within 200ms`) {
		t.Fatalf("err = %v, want a timeout naming the job", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Run took %s, the timeout didn't stop ShellCheck", d)
	}
}

func TestWithStderr(t *testing.T) {
	base := errors.New("exit status 3")
	if got := withStderr(base, ""); got != base {
		t.Errorf("no stderr: got %v", got)
	}
	long := withStderr(base, strings.Repeat("x", 400)).Error()
	if !strings.HasSuffix(long, "…") || len(long) > 330 {
		t.Errorf("long stderr not cut: %d bytes", len(long))
	}
	if got := withStderr(base, "line one\n  line two\n").Error(); got != "exit status 3: line one line two" {
		t.Errorf("got %q", got)
	}
	if !errors.Is(withStderr(base, "x"), base) {
		t.Error("withStderr must wrap the error")
	}
}

func TestRun_EmptyPipelineDoesNotCallShellcheck(t *testing.T) {
	record := useFake(t, sc2086, 1)
	if got := mustRun(t, parseDoc(t, "job:\n  script: []\n"), os.Args[0]); len(got) != 0 {
		t.Fatalf("expected no findings, got %+v", got)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Error("shellcheck should not run for a pipeline without script lines")
	}
}

func TestResolveBinary(t *testing.T) {
	if _, err := resolveBinary(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("an explicit path that doesn't exist should be an error")
	}

	dir := t.TempDir()
	t.Setenv("PATH", dir)
	if _, err := resolveBinary(""); err == nil {
		t.Error("an empty PATH should not find shellcheck")
	}

	name := "shellcheck"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o700); err != nil { //nolint:gosec // executable stub for LookPath
		t.Fatal(err)
	}
	got, err := resolveBinary("")
	if err != nil {
		t.Fatalf("shellcheck on PATH not found: %v", err)
	}
	if filepath.Base(got) != name {
		t.Errorf("resolved %q", got)
	}
}
