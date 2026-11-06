// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var now = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)

func runJSON(id int, name, event, branch string, minutes float64) string {
	end := now.Add(time.Duration(minutes * float64(time.Minute)))
	return fmt.Sprintf(`{"id":%d,"name":%q,"event":%q,"head_branch":%q,"run_started_at":%q,"updated_at":%q}`,
		id, name, event, branch, now.Format(time.RFC3339), end.Format(time.RFC3339))
}

// workflowsJSON lists the workflow with runs, and two the search must skip.
const workflowsJSON = `{"workflows":[
	{"id":1,"path":".github/workflows/ci.yml","state":"active"},
	{"id":2,"path":"dynamic/dependabot/dependabot-updates","state":"active"},
	{"id":3,"path":".github/workflows/old.yml","state":"disabled_manually"}]}`

func writeRuns(w io.Writer, total int, runs ...string) {
	_, _ = fmt.Fprintf(w, `{"total_count":%d,"workflow_runs":[%s]}`, total, strings.Join(runs, ","))
}

// api serves the runs as those of one workflow, and two jobs for every run.
func api(t *testing.T, runs ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("no token on the request")
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/workflows"):
			_, _ = fmt.Fprint(w, workflowsJSON)
		case strings.HasSuffix(r.URL.Path, "/jobs"):
			start, end := now.Format(time.RFC3339), now.Add(2*time.Minute).Format(time.RFC3339)
			_, _ = fmt.Fprintf(w, `{"jobs":[{"name":"Test","conclusion":"success","started_at":%q,"completed_at":%q},
				{"name":"Skipped","conclusion":"skipped","started_at":null,"completed_at":null}]}`, start, end)
		case strings.HasSuffix(r.URL.Path, "/workflows/1/runs"):
			if got := r.URL.Query().Get("created"); got != ">=2026-11-02" {
				t.Errorf("created = %q", got)
			}
			writeRuns(w, len(runs), runs...)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	opt := append([]string{"-now", now.Format(time.RFC3339)}, args...)
	code := realMain(opt, "secret", &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestWithinBudget(t *testing.T) {
	srv := api(t,
		runJSON(1, "CI", "pull_request", "fix/a", 3),
		runJSON(2, "CI", "push", "main", 4),
		runJSON(3, "CI", "push", "feature", 500),
		runJSON(4, "Release", "push", "v1.0.0", 500),
		runJSON(5, "Scorecard", "schedule", "main", 500),
	)
	path := filepath.Join(t.TempDir(), "record.jsonl")
	code, out, stderr := cli(t, "-api", srv.URL, "-record", path)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "within the budget of 10 minutes") || !strings.Contains(out, "| CI | 2 | 4.0 | 4.0 | 4.0 |") {
		t.Errorf("report:\n%s", out)
	}
	if strings.Contains(out, "Release") || strings.Contains(out, "Scorecard") {
		t.Errorf("report counts runs that aren't from pull requests or main:\n%s", out)
	}
	if strings.Contains(out, "Skipped") {
		t.Errorf("report lists a job that didn't succeed:\n%s", out)
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: a temporary file of this test
	if err != nil {
		t.Fatal(err)
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Schema != schema || rec.Date != "2026-11-09T08:00:00Z" || len(rec.Workflows) != 1 || rec.Jobs[0].Runs != 2 {
		t.Errorf("record: %s", data)
	}
}

func TestOverBudget(t *testing.T) {
	var runs []string
	for i := range 5 {
		runs = append(runs, runJSON(i, "CI|main", "pull_request", "x", 11))
	}
	code, out, _ := cli(t, "-api", api(t, runs...).URL, "-jobs-of", "none")
	if code != exitBudget {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out, `Over the budget of 10 minutes (p90):** CI|main (11.0)`) || !strings.Contains(out, `| CI\|main | 5 |`) {
		t.Errorf("report:\n%s", out)
	}
}

func TestFewRunsDontCountAgainstTheBudget(t *testing.T) {
	code, _, _ := cli(t, "-api", api(t, runJSON(1, "CI", "push", "main", 60)).URL)
	if code != exitOK {
		t.Errorf("exit %d", code)
	}
}

func TestSampleLimitsJobRequests(t *testing.T) {
	code, out, _ := cli(t, "-api", api(t,
		runJSON(1, "CI", "push", "main", 3),
		runJSON(2, "CI", "push", "main", 3),
		runJSON(3, "CI", "push", "main", 3),
	).URL, "-sample", "2")
	if code != exitOK || !strings.Contains(out, "| Test | 2 |") {
		t.Errorf("exit %d, report:\n%s", code, out)
	}
}

// pagedAPI serves total runs of one workflow, 100 per page, and counts requests.
func pagedAPI(t *testing.T, total int, requests *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/actions/workflows") {
			_, _ = fmt.Fprint(w, workflowsJSON)
			return
		}
		*requests++
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		count := min(total-(page-1)*perPage, perPage)
		runs := make([]string, max(count, 0))
		for i := range runs {
			runs[i] = runJSON(i, "CI", "push", "main", 3)
		}
		writeRuns(w, total, runs...)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPagination(t *testing.T) {
	for _, tc := range []struct{ total, pages int }{{perPage + 1, 2}, {2 * perPage, 2}, {maxRuns, 10}} {
		requests := 0
		code, out, stderr := cli(t, "-api", pagedAPI(t, tc.total, &requests).URL, "-sample", "0")
		if code != exitOK || requests != tc.pages || !strings.Contains(out, fmt.Sprintf("| CI | %d |", tc.total)) {
			t.Errorf("%d runs: exit %d, %d requests, want %d: %s\n%s", tc.total, code, requests, tc.pages, stderr, out)
		}
	}
}

func TestWorkflowListPagination(t *testing.T) {
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/runs") {
			writeRuns(w, 0)
			return
		}
		pages++
		count := perPage
		if r.URL.Query().Get("page") == "2" {
			count = 0
		}
		list := make([]string, count)
		for i := range list {
			list[i] = `{"id":1,"path":".github/workflows/ci.yml","state":"active"}`
		}
		_, _ = fmt.Fprintf(w, `{"workflows":[%s]}`, strings.Join(list, ","))
	}))
	defer srv.Close()
	if code, _, stderr := cli(t, "-api", srv.URL); code != exitOK || pages != 2 {
		t.Errorf("exit %d, %d pages: %s", code, pages, stderr)
	}
}

// TestWorkflowOverTheSearchLimit: without total_count a search just ends at
// 1,000 runs, and the record would claim a week it doesn't cover (#1241).
func TestWorkflowOverTheSearchLimit(t *testing.T) {
	requests := 0
	path := filepath.Join(t.TempDir(), "record.jsonl")
	code, _, stderr := cli(t, "-api", pagedAPI(t, maxRuns+1, &requests).URL, "-record", path)
	if code != exitError || !strings.Contains(stderr, "1001 runs") {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a record was written: %v", err)
	}
}

func TestErrors(t *testing.T) {
	status := func(code int) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		t.Cleanup(srv.Close)
		return srv
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "not json") }))
	defer bad.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	jobsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/workflows"):
			_, _ = fmt.Fprint(w, workflowsJSON)
		case strings.HasSuffix(r.URL.Path, "/jobs"):
			w.WriteHeader(http.StatusNotFound)
		default:
			writeRuns(w, 1, runJSON(1, "CI", "push", "main", 3))
		}
	}))
	defer jobsFail.Close()
	runsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/actions/workflows") {
			_, _ = fmt.Fprint(w, workflowsJSON)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer runsFail.Close()

	for name, args := range map[string][]string{
		"not found":    {"-api", status(http.StatusNotFound).URL},
		"server error": {"-api", status(http.StatusBadGateway).URL},
		"not JSON":     {"-api", bad.URL},
		"no server":    {"-api", closed.URL},
		"bad URL":      {"-api", "http://bad host"},
		"jobs fail":    {"-api", jobsFail.URL},
		"runs fail":    {"-api", runsFail.URL},
		"bad flag":     {"-nonsense"},
		"bad now":      {"-now", "yesterday"},
		"record path":  {"-api", api(t).URL, "-record", filepath.Join(t.TempDir(), "missing", "record.jsonl")},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := cli(t, args...); code != exitError {
				t.Errorf("exit %d, want %d", code, exitError)
			}
		})
	}
}

func TestServerErrorIsRetried(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprint(w, `{"workflows":[]}`)
	}))
	defer srv.Close()
	if code, _, stderr := cli(t, "-api", srv.URL); code != exitOK || calls != 2 {
		t.Errorf("exit %d after %d calls: %s", code, calls, stderr)
	}
}

func TestStatsPercentiles(t *testing.T) {
	var ten []float64
	for i := 1; i <= 10; i++ {
		ten = append(ten, float64(i))
	}
	got := stats(map[string][]float64{"b": ten, "a": {1, 2}, "c": {10}})
	if got[0].Name != "c" || got[1].Name != "b" || got[1].P90 != 9 || got[1].Median != 6 || got[1].Max != 10 {
		t.Errorf("%+v", got)
	}
	if got[2].Name != "a" || got[2].P90 != 2 {
		t.Errorf("%+v", got)
	}
	tied := stats(map[string][]float64{"z": {1}, "y": {1}})
	if tied[0].Name != "y" {
		t.Errorf("ties aren't sorted by name: %+v", tied)
	}
}

// TestEveryJobHasATimeout keeps a hanging job from running until GitHub's limit
// of six hours (#1239). A job that calls a reusable workflow can't set one; the
// jobs of that workflow do.
func TestEveryJobHasATimeout(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file) //nolint:gosec // G304: a file of this repository
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			Jobs map[string]struct {
				Uses    string `yaml:"uses"`
				Timeout *int   `yaml:"timeout-minutes"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for name, job := range workflow.Jobs {
			if job.Uses == "" && job.Timeout == nil {
				t.Errorf("%s: job %s has no timeout-minutes", filepath.Base(file), name)
			}
		}
	}
}
