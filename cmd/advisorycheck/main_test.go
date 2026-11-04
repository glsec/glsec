// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const listHead = `- id: "CVE-2026-0001"
  aliases: [GHSA-aaaa-bbbb-cccc]
  repo: owner/name
  kind: cve
- id: "Some Campaign"
  kind: campaign
`

func writeList(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "advisories.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// service answers with the given status and body per path; any other path is
// a 404.
func service(t *testing.T, answers map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := answers[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runCheck(t *testing.T, list string, srv *httptest.Server) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), []string{
		"-file", writeList(t, list), "-cve-base", srv.URL + "/cve/", "-github-base", srv.URL + "/",
	}, &out, &errb, "token")
	return code, out.String() + errb.String()
}

func TestRun(t *testing.T) {
	const published = `{"cveMetadata":{"state":"PUBLISHED"}}`
	const active = `{"state":"published","withdrawn_at":null}`
	tests := []struct {
		name    string
		answers map[string]string
		code    int
		want    string
	}{
		{"valid", map[string]string{
			"/cve/CVE-2026-0001": published,
			"/repos/owner/name/security-advisories/GHSA-aaaa-bbbb-cccc": active,
		}, exitOK, "Checked 2 ids: 0 findings, 0 not checked."},
		{"rejected", map[string]string{
			"/cve/CVE-2026-0001": `{"cveMetadata":{"state":"REJECTED"}}`,
			"/repos/owner/name/security-advisories/GHSA-aaaa-bbbb-cccc": active,
		}, exitFinding, "- CVE-2026-0001: rejected"},
		{"withdrawn", map[string]string{
			"/cve/CVE-2026-0001": published,
			"/repos/owner/name/security-advisories/GHSA-aaaa-bbbb-cccc": `{"withdrawn_at":"2026-11-01T00:00:00Z"}`,
		}, exitFinding, "- GHSA-aaaa-bbbb-cccc: withdrawn"},
		{"withdrawn state", map[string]string{
			"/cve/CVE-2026-0001": published,
			"/repos/owner/name/security-advisories/GHSA-aaaa-bbbb-cccc": `{"state":"withdrawn"}`,
		}, exitFinding, "- GHSA-aaaa-bbbb-cccc: withdrawn"},
		{"unknown", map[string]string{"/cve/CVE-2026-0001": published}, exitFinding, "## Unknown to the service"},
		{"new state", map[string]string{
			"/cve/CVE-2026-0001": `{"cveMetadata":{"state":"OTHER"}}`,
			"/repos/owner/name/security-advisories/GHSA-aaaa-bbbb-cccc": active,
		}, exitNotKnown, `unexpected state "OTHER"`},
		{"bad json", map[string]string{
			"/cve/CVE-2026-0001": "<html>",
			"/repos/owner/name/security-advisories/GHSA-aaaa-bbbb-cccc": active,
		}, exitNotKnown, "## Could not be checked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fastChecker(t, service(t, tt.answers))
			got := []result{
				c.check(context.Background(), target{id: "CVE-2026-0001"}),
				c.check(context.Background(), target{id: "GHSA-aaaa-bbbb-cccc", repo: "owner/name"}),
			}
			var out bytes.Buffer
			if code := report(&out, got); code != tt.code {
				t.Errorf("exit %d, want %d:\n%s", code, tt.code, out.String())
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Errorf("report lacks %q:\n%s", tt.want, out.String())
			}
		})
	}
}

func fastChecker(t *testing.T, srv *httptest.Server) *checker {
	t.Helper()
	return &checker{client: srv.Client(), cveBase: srv.URL + "/cve/", ghBase: srv.URL + "/", ghToken: "token", attempts: 3, backoff: time.Millisecond}
}

// A finding outranks a failed lookup: both are in the report, and exit 1 is
// what opens the issue.
func TestReport_FindingOutranksFailure(t *testing.T) {
	var out bytes.Buffer
	code := report(&out, []result{
		{id: "CVE-2026-0001", state: stateInvalid, detail: "rejected"},
		{id: "CVE-2026-0002", state: stateNotKnown, detail: "503"},
	})
	if code != exitFinding || !strings.Contains(out.String(), "Could not be checked") {
		t.Errorf("exit %d:\n%s", code, out.String())
	}
}

func TestRun_GlobalGHSAAndCampaign(t *testing.T) {
	srv := service(t, map[string]string{
		"/cve/CVE-2026-0001":              `{"cveMetadata":{"state":"PUBLISHED"}}`,
		"/advisories/GHSA-aaaa-bbbb-cccc": `{"withdrawn_at":null}`,
	})
	list := `- {id: "CVE-2026-0001", aliases: [GHSA-aaaa-bbbb-cccc], kind: cve}
- {id: "Some Campaign", kind: campaign}
`
	code, out := runCheck(t, list, srv)
	if code != exitOK || !strings.Contains(out, "Checked 2 ids") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestRun_UsesListAndReportsFinding(t *testing.T) {
	srv := service(t, map[string]string{"/cve/CVE-2026-0001": `{"cveMetadata":{"state":"REJECTED"}}`})
	code, out := runCheck(t, listHead, srv)
	if code != exitFinding || !strings.Contains(out, "CVE-2026-0001: rejected") || !strings.Contains(out, "GHSA-aaaa-bbbb-cccc: not found") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

func TestRun_BadInput(t *testing.T) {
	srv := service(t, nil)
	for name, list := range map[string]string{
		"not yaml":  "{",
		"bad id":    `- {id: "CVE-1", kind: cve}` + "\n",
		"bad alias": `- {id: "CVE-2026-0001", aliases: ["../x"], kind: cve}` + "\n",
		"bad repo":  `- {id: "CVE-2026-0001", repo: "a/b/../c", kind: cve}` + "\n",
		"no ids":    `- {id: "Some Campaign", kind: campaign}` + "\n",
	} {
		if code, _ := runCheck(t, list, srv); code != exitNotKnown {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	var out bytes.Buffer
	if code := run(context.Background(), []string{"-nope"}, &out, &out, ""); code != exitNotKnown {
		t.Errorf("bad flag: exit %d", code)
	}
	if code := run(context.Background(), []string{"-file", filepath.Join(t.TempDir(), "missing")}, &out, &out, ""); code != exitNotKnown {
		t.Errorf("missing file: exit %d", code)
	}
}

func TestFetch_RetriesAndGivesUp(t *testing.T) {
	var calls atomic.Int32
	failures := int32(2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= failures {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"cveMetadata":{"state":"PUBLISHED"}}`))
	}))
	defer srv.Close()
	c := fastChecker(t, srv)
	if r := c.check(context.Background(), target{id: "CVE-2026-0001"}); r.state != stateValid {
		t.Errorf("recovered lookup: %+v", r)
	}
	calls.Store(0)
	failures = 10
	r := c.check(context.Background(), target{id: "CVE-2026-0001"})
	if r.state != stateNotKnown || !strings.Contains(r.detail, "503") {
		t.Errorf("persistent failure: %+v", r)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("%d attempts, want 3", got)
	}
}

func TestFetch_CancelledWhileWaiting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := fastChecker(t, srv)
	c.backoff = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if r := c.check(ctx, target{id: "CVE-2026-0001"}); r.state != stateNotKnown {
		t.Errorf("got %+v", r)
	}
}

func TestGet_Failures(t *testing.T) {
	c := &checker{client: http.DefaultClient, ghBase: "http://127.0.0.1:1/"}
	if _, err := c.get(context.Background(), "http://127.0.0.1:1/x", nil, true); err == nil {
		t.Error("no error from a closed port")
	}
	if _, err := c.get(context.Background(), "://bad", nil, true); err == nil {
		t.Error("no error from a bad URL")
	}
}

// The token is for GitHub only.
func TestGet_TokenOnlyForGitHub(t *testing.T) {
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"cveMetadata":{"state":"PUBLISHED"}}`))
	}))
	defer srv.Close()
	c := fastChecker(t, srv)
	c.ghBase = "https://api.github.com.invalid/"
	c.check(context.Background(), target{id: "CVE-2026-0001"})
	if got := auth.Load(); got != "" {
		t.Errorf("cve.org got %q", got)
	}
	c.ghBase = srv.URL + "/"
	c.check(context.Background(), target{id: "GHSA-aaaa-bbbb-cccc"})
	if got := auth.Load(); got != "Bearer token" {
		t.Errorf("GitHub got %q", got)
	}
}

// A token the organisation refuses must not cost the lookup: the advisory is
// public. A 403 without the token is a failure like any other.
func TestFetch_ForbiddenTokenFallsBack(t *testing.T) {
	refuseAnonymous := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || refuseAnonymous {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"state":"published"}`))
	}))
	defer srv.Close()
	c := fastChecker(t, srv)
	if r := c.check(context.Background(), target{id: "GHSA-aaaa-bbbb-cccc", repo: "owner/name"}); r.state != stateValid {
		t.Errorf("fallback: %+v", r)
	}
	refuseAnonymous = true
	if r := c.check(context.Background(), target{id: "GHSA-aaaa-bbbb-cccc", repo: "owner/name"}); r.state != stateNotKnown {
		t.Errorf("refused both ways: %+v", r)
	}
}

// The real list has to load, or the weekly run fails on the file instead of
// checking it.
func TestLoad_RealList(t *testing.T) {
	targets, err := load("../../docs/advisories.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("no ids")
	}
}
