// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Command ciduration reports how long the GitHub Actions workflows of this
// repository took, for the weekly workflow (#1239). It is not part of go test,
// so that tests do not depend on outside services, and it is not released.
//
// It counts successful runs of pull requests and of pushes to main: a failed
// run stops early, and a release or a scheduled check says nothing about how
// long a contributor waits. A run's duration includes its time in the queue.
// Each workflow is searched on its own, because a search returns at most 1,000
// runs and all workflows together have more than that in a week (#1241).
//
// The exit code says what the workflow has to do: 0 nothing, 1 a workflow's p90
// is over the budget, 2 the numbers could not be read. The report goes to
// stdout as Markdown.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	exitOK     = 0
	exitBudget = 1
	exitError  = 2

	maxAttempts  = 3
	maxBody      = 16 << 20
	maxRuns      = 1000 // the API returns no more for one search
	perPage      = 100
	requestLimit = 30 * time.Second
	schema       = 1
)

// run is what the report needs of one workflow run.
type run struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Event      string    `json:"event"`
	HeadBranch string    `json:"head_branch"`
	Started    time.Time `json:"run_started_at"`
	Updated    time.Time `json:"updated_at"`
}

// workflow is what the search needs of one workflow.
type workflow struct {
	ID    int64  `json:"id"`
	Path  string `json:"path"`
	State string `json:"state"`
}

// job is what the report needs of one job of a run.
type job struct {
	Name       string     `json:"name"`
	Conclusion string     `json:"conclusion"`
	Started    *time.Time `json:"started_at"`
	Completed  *time.Time `json:"completed_at"`
}

// stat is one line of the report and the record, in minutes.
type stat struct {
	Name   string  `json:"name"`
	Runs   int     `json:"runs"`
	Median float64 `json:"median"`
	P90    float64 `json:"p90"`
	Max    float64 `json:"max"`
}

// record is one line of the data file.
type record struct {
	Schema    int     `json:"schema"`
	Date      string  `json:"date"`
	Days      int     `json:"days"`
	Budget    float64 `json:"budget_minutes"`
	Workflows []stat  `json:"workflows"`
	Jobs      []stat  `json:"jobs"`
}

type options struct {
	api, repo, token, jobsOf, recordPath string
	days, sample, minRuns                int
	budget                               float64
	now                                  time.Time
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Getenv("GITHUB_TOKEN"), os.Stdout, os.Stderr))
}

func realMain(args []string, token string, stdout, stderr io.Writer) int {
	opt := options{token: token}
	var at string
	flags := flag.NewFlagSet("ciduration", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opt.api, "api", "https://api.github.com", "GitHub API base URL")
	flags.StringVar(&opt.repo, "repo", "glsec/glsec", "repository")
	flags.StringVar(&opt.jobsOf, "jobs-of", "CI", "workflow whose jobs the report lists")
	flags.StringVar(&opt.recordPath, "record", "", "write the record as one JSON line to this file")
	flags.IntVar(&opt.days, "days", 7, "days to look back")
	flags.IntVar(&opt.sample, "sample", 30, "recent runs to read the jobs of")
	flags.IntVar(&opt.minRuns, "min-runs", 5, "fewest runs for a workflow to count against the budget")
	flags.Float64Var(&opt.budget, "budget", 10, "maximum p90 of a workflow in minutes")
	flags.StringVar(&at, "now", "", "the time to report for, RFC 3339 (default: the current time)")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	opt.now = time.Now()
	if at != "" {
		parsed, err := time.Parse(time.RFC3339, at)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return exitError
		}
		opt.now = parsed
	}

	ctx := context.Background()
	runs, err := fetchRuns(ctx, opt)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitError
	}
	jobs, err := fetchJobs(ctx, opt, runs)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return exitError
	}

	rec := record{
		Schema:    schema,
		Date:      opt.now.UTC().Format(time.RFC3339),
		Days:      opt.days,
		Budget:    opt.budget,
		Workflows: workflowStats(runs),
		Jobs:      jobStats(jobs),
	}
	if opt.recordPath != "" {
		if err := writeRecord(opt.recordPath, rec); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return exitError
		}
	}
	over := overBudget(rec.Workflows, opt)
	writeReport(stdout, rec, over)
	if len(over) > 0 {
		return exitBudget
	}
	return exitOK
}

// counted reports whether a run says how long a contributor waits.
func counted(r run) bool {
	return r.Event == "pull_request" || r.Event == "push" && r.HeadBranch == "main"
}

// fetchWorkflows lists the active workflows of the repository. Dependabot's and
// other built-in ones have a path outside .github/workflows.
func fetchWorkflows(ctx context.Context, opt options) ([]workflow, error) {
	var workflows []workflow
	for page := 1; ; page++ {
		var body struct {
			Workflows []workflow `json:"workflows"`
		}
		path := fmt.Sprintf("/repos/%s/actions/workflows?per_page=%d&page=%d", opt.repo, perPage, page)
		if err := get(ctx, opt, path, &body); err != nil {
			return nil, err
		}
		for _, w := range body.Workflows {
			if w.State == "active" && strings.HasPrefix(w.Path, ".github/workflows/") {
				workflows = append(workflows, w)
			}
		}
		if len(body.Workflows) < perPage {
			return workflows, nil
		}
	}
}

func fetchRuns(ctx context.Context, opt options) ([]run, error) {
	workflows, err := fetchWorkflows(ctx, opt)
	if err != nil {
		return nil, err
	}
	var runs []run
	for _, w := range workflows {
		found, err := fetchWorkflowRuns(ctx, opt, w)
		if err != nil {
			return nil, err
		}
		runs = append(runs, found...)
	}
	return runs, nil
}

// fetchWorkflowRuns fails rather than return a part of the window: a record that
// says 7 days must cover 7 days.
func fetchWorkflowRuns(ctx context.Context, opt options, w workflow) ([]run, error) {
	since := opt.now.UTC().AddDate(0, 0, -opt.days).Format("2006-01-02")
	var runs []run
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("status", "success")
		q.Set("created", ">="+since)
		q.Set("per_page", fmt.Sprint(perPage))
		q.Set("page", fmt.Sprint(page))
		var body struct {
			Total int   `json:"total_count"`
			Runs  []run `json:"workflow_runs"`
		}
		path := fmt.Sprintf("/repos/%s/actions/workflows/%d/runs?%s", opt.repo, w.ID, q.Encode())
		if err := get(ctx, opt, path, &body); err != nil {
			return nil, err
		}
		if body.Total > maxRuns {
			return nil, fmt.Errorf("%s: %d runs since %s, a search returns at most %d", w.Path, body.Total, since, maxRuns)
		}
		for _, r := range body.Runs {
			if counted(r) {
				runs = append(runs, r)
			}
		}
		if len(body.Runs) < perPage || page*perPage >= body.Total {
			return runs, nil
		}
	}
}

// fetchJobs reads the jobs of the newest runs of one workflow. The API lists a
// workflow's runs newest first. One request per run, so the sample keeps a weekly
// run well inside the rate limit.
func fetchJobs(ctx context.Context, opt options, runs []run) ([]job, error) {
	var jobs []job
	read := 0
	for _, r := range runs {
		if r.Name != opt.jobsOf {
			continue
		}
		if read == opt.sample {
			break
		}
		read++
		var body struct {
			Jobs []job `json:"jobs"`
		}
		path := fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?per_page=%d", opt.repo, r.ID, perPage)
		if err := get(ctx, opt, path, &body); err != nil {
			return nil, err
		}
		jobs = append(jobs, body.Jobs...)
	}
	return jobs, nil
}

func get(ctx context.Context, opt options, path string, out any) error {
	var err error
	for range maxAttempts {
		var retry bool
		retry, err = getOnce(ctx, opt, path, out)
		if err == nil || !retry {
			return err
		}
	}
	return err
}

// getOnce reports whether trying again can help: a server error or a broken
// connection can pass, a 404 or a bad token doesn't.
func getOnce(ctx context.Context, opt options, path string, out any) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, requestLimit)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opt.api+path, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if opt.token != "" {
		req.Header.Set("Authorization", "Bearer "+opt.token)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: the URL comes from a flag of this tool
	if err != nil {
		return true, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode >= http.StatusInternalServerError, fmt.Errorf("%s: %s", path, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return false, nil
}

func workflowStats(runs []run) []stat {
	times := map[string][]float64{}
	for _, r := range runs {
		times[r.Name] = append(times[r.Name], r.Updated.Sub(r.Started).Minutes())
	}
	return stats(times)
}

func jobStats(jobs []job) []stat {
	times := map[string][]float64{}
	for _, j := range jobs {
		if j.Conclusion == "success" && j.Started != nil && j.Completed != nil {
			times[j.Name] = append(times[j.Name], j.Completed.Sub(*j.Started).Minutes())
		}
	}
	return stats(times)
}

// stats sorts the slowest first, by p90, then by name to keep records stable.
func stats(times map[string][]float64) []stat {
	out := make([]stat, 0, len(times))
	for name, t := range times {
		slices.Sort(t)
		out = append(out, stat{
			Name:   name,
			Runs:   len(t),
			Median: rounded(t[len(t)/2]),
			P90:    rounded(t[(len(t)*9+9)/10-1]),
			Max:    rounded(t[len(t)-1]),
		})
	}
	slices.SortFunc(out, func(a, b stat) int {
		return cmp.Or(cmp.Compare(b.P90, a.P90), cmp.Compare(a.Name, b.Name))
	})
	return out
}

func rounded(minutes float64) float64 {
	return float64(int(minutes*10+0.5)) / 10
}

// overBudget leaves out workflows with few runs: their p90 is one outlier.
func overBudget(workflows []stat, opt options) []stat {
	var over []stat
	for _, s := range workflows {
		if s.P90 > opt.budget && s.Runs >= opt.minRuns {
			over = append(over, s)
		}
	}
	return over
}

func writeRecord(path string, rec record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func writeReport(w io.Writer, rec record, over []stat) {
	_, _ = fmt.Fprintf(w, "## GitHub Actions durations, last %d days\n\n", rec.Days)
	if len(over) == 0 {
		_, _ = fmt.Fprintf(w, "Every workflow is within the budget of %g minutes (p90).\n\n", rec.Budget)
	} else {
		names := make([]string, len(over))
		for i, s := range over {
			names[i] = fmt.Sprintf("%s (%.1f)", s.Name, s.P90)
		}
		_, _ = fmt.Fprintf(w, "**Over the budget of %g minutes (p90):** %s\n\n", rec.Budget, strings.Join(names, ", "))
	}
	writeTable(w, "Workflow", rec.Workflows)
	_, _ = fmt.Fprintln(w)
	writeTable(w, "Job", rec.Jobs)
}

func writeTable(w io.Writer, title string, rows []stat) {
	_, _ = fmt.Fprintf(w, "| %s | Runs | Median | p90 | Max |\n| --- | --- | --- | --- | --- |\n", title)
	for _, s := range rows {
		name := strings.ReplaceAll(s.Name, "|", `\|`)
		_, _ = fmt.Fprintf(w, "| %s | %d | %.1f | %.1f | %.1f |\n", name, s.Runs, s.Median, s.P90, s.Max)
	}
}
