// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Command advisorycheck asks cve.org and GitHub whether the CVEs and GHSAs in
// docs/advisories.yml are still valid, for the weekly workflow (#1174). It is
// not part of go test, so that tests and pull requests do not depend on outside
// services, and it is not released.
//
// The exit code says what the workflow has to do: 0 nothing, 1 an id was
// rejected, withdrawn or is unknown, 2 at least one id could not be checked.
// The report goes to stdout as Markdown.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	exitOK       = 0
	exitFinding  = 1
	exitNotKnown = 2

	maxAttempts  = 3
	maxBody      = 8 << 20
	requestLimit = 30 * time.Second
)

var (
	idRe   = regexp.MustCompile(`^(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$`)
	repoRe = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)
)

// entry is what the check needs of one line of docs/advisories.yml.
type entry struct {
	ID      string   `yaml:"id"`
	Aliases []string `yaml:"aliases"`
	Repo    string   `yaml:"repo"`
	Kind    string   `yaml:"kind"`
}

// target is one id to ask about.
type target struct {
	id, repo string
}

// state is the answer for one id.
type state int

const (
	stateValid    state = iota
	stateInvalid        // rejected or withdrawn
	stateUnknown        // the service has no such id
	stateNotKnown       // the service could not be asked
)

// result is one id's answer, with detail for the report.
type result struct {
	id     string
	state  state
	detail string
}

// checker asks the services. The base URLs and the wait are fields so that the
// tests can point it at a local server.
type checker struct {
	client   *http.Client
	cveBase  string
	ghBase   string
	ghToken  string
	backoff  time.Duration
	attempts int
}

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, os.Getenv("GITHUB_TOKEN")))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, token string) int {
	flags := flag.NewFlagSet("advisorycheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("file", "docs/advisories.yml", "the advisory list")
	cveBase := flags.String("cve-base", "https://cveawg.mitre.org/api/cve/", "CVE record API")
	ghBase := flags.String("github-base", "https://api.github.com/", "GitHub API")
	if err := flags.Parse(args); err != nil {
		return exitNotKnown
	}
	targets, err := load(*file)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "advisorycheck:", err)
		return exitNotKnown
	}
	c := &checker{
		client: &http.Client{Timeout: requestLimit}, cveBase: *cveBase, ghBase: *ghBase,
		ghToken: token, backoff: 5 * time.Second, attempts: maxAttempts,
	}
	results := make([]result, 0, len(targets))
	for _, t := range targets {
		results = append(results, c.check(ctx, t))
	}
	return report(stdout, results)
}

// load reads the list and returns every CVE and GHSA in it, aliases included.
// A campaign has no id to ask about.
func load(file string) ([]target, error) {
	raw, err := os.ReadFile(file) // #nosec G304 -- a path the workflow passes
	if err != nil {
		return nil, err
	}
	var entries []entry
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var targets []target
	for _, e := range entries {
		if e.Kind == "campaign" {
			continue
		}
		if e.Repo != "" && !repoRe.MatchString(e.Repo) {
			return nil, fmt.Errorf("%s: %s: bad repo %q", file, e.ID, e.Repo)
		}
		for _, id := range append([]string{e.ID}, e.Aliases...) {
			if !idRe.MatchString(id) {
				return nil, fmt.Errorf("%s: bad id %q", file, id)
			}
			targets = append(targets, target{id: id, repo: e.Repo})
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%s: no ids", file)
	}
	return targets, nil
}

func (c *checker) check(ctx context.Context, t target) result {
	if strings.HasPrefix(t.id, "CVE-") {
		return c.checkCVE(ctx, t.id)
	}
	return c.checkGHSA(ctx, t)
}

func (c *checker) checkCVE(ctx context.Context, id string) result {
	var body struct {
		Metadata struct {
			State string `json:"state"`
		} `json:"cveMetadata"`
	}
	res, done := c.fetch(ctx, id, c.cveBase+url.PathEscape(id), &body)
	if done {
		return res
	}
	switch body.Metadata.State {
	case "PUBLISHED":
		return result{id: id, state: stateValid}
	case "REJECTED":
		return result{id: id, state: stateInvalid, detail: "rejected"}
	}
	return result{id: id, state: stateNotKnown, detail: fmt.Sprintf("unexpected state %q", body.Metadata.State)}
}

// checkGHSA reads the entry's repository when it has one: such an advisory is
// not in the global database, whose answer would be a 404.
func (c *checker) checkGHSA(ctx context.Context, t target) result {
	path := "advisories/" + url.PathEscape(t.id)
	if t.repo != "" {
		path = "repos/" + t.repo + "/security-advisories/" + url.PathEscape(t.id)
	}
	var body struct {
		State       string  `json:"state"`
		WithdrawnAt *string `json:"withdrawn_at"`
	}
	res, done := c.fetch(ctx, t.id, c.ghBase+path, &body)
	if done {
		return res
	}
	if body.WithdrawnAt != nil || body.State == "withdrawn" {
		return result{id: t.id, state: stateInvalid, detail: "withdrawn"}
	}
	return result{id: t.id, state: stateValid}
}

// fetch decodes the answer into out. When it returns done, the result is
// final: the service does not know the id, or it could not be asked. A failure
// the service may recover from is retried.
func (c *checker) fetch(ctx context.Context, id, target string, out any) (result, bool) {
	var err error
	for attempt := range c.attempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return result{id: id, state: stateNotKnown, detail: ctx.Err().Error()}, true
			case <-time.After(c.backoff << (attempt - 1)):
			}
		}
		var status int
		status, err = c.get(ctx, target, out, true)
		// Some organisations refuse the workflow's token. Their published
		// advisories are public, so ask again without it.
		if status == http.StatusForbidden && c.ghToken != "" {
			status, err = c.get(ctx, target, out, false)
		}
		if status == http.StatusNotFound {
			return result{id: id, state: stateUnknown, detail: "not found"}, true
		}
		if err == nil {
			return result{}, false
		}
	}
	return result{id: id, state: stateNotKnown, detail: err.Error()}, true
}

func (c *checker) get(ctx context.Context, target string, out any, useToken bool) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "glsec-advisory-check")
	req.Header.Set("Accept", "application/json")
	if useToken && c.ghToken != "" && strings.HasPrefix(target, c.ghBase) {
		req.Header.Set("Authorization", "Bearer "+c.ghToken)
	}
	resp, err := c.client.Do(req) // #nosec G704 -- base URLs are flags of the workflow
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, errors.New(resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out); err != nil {
		return resp.StatusCode, fmt.Errorf("decode: %w", err)
	}
	return resp.StatusCode, nil
}

// report prints what needs attention and returns the exit code. A finding
// outranks a failed lookup, because it needs a person either way.
func report(w io.Writer, results []result) int {
	section := func(title string, s state) int {
		n := 0
		for _, r := range results {
			if r.state != s {
				continue
			}
			if n == 0 {
				_, _ = fmt.Fprintf(w, "## %s\n\n", title)
			}
			n++
			_, _ = fmt.Fprintf(w, "- %s: %s\n", r.id, r.detail)
		}
		if n > 0 {
			_, _ = fmt.Fprintln(w)
		}
		return n
	}
	findings := section("Rejected or withdrawn", stateInvalid)
	findings += section("Unknown to the service", stateUnknown)
	failed := section("Could not be checked", stateNotKnown)
	_, _ = fmt.Fprintf(w, "Checked %d ids: %d findings, %d not checked.\n", len(results), findings, failed)
	switch {
	case findings > 0:
		return exitFinding
	case failed > 0:
		return exitNotKnown
	}
	return exitOK
}
