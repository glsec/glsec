// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/glsec/glsec/rules"
)

// The list of known attacks (#1173): docs/advisories.yml says which attacks
// glsec sees, at which severity, and which not. These tests keep it true: the
// structure, the fixtures and both directions of the links to the rule docs.

type advisoryRule struct {
	Rule     string `yaml:"rule"`
	Severity string `yaml:"severity"`
}

type advisoryStep struct {
	Step   string   `yaml:"step"`
	Rules  []string `yaml:"rules"`
	Reason string   `yaml:"reason"`
}

type advisory struct {
	ID       string         `yaml:"id"`
	Aliases  []string       `yaml:"aliases"`
	Repo     string         `yaml:"repo"`
	Kind     string         `yaml:"kind"`
	Product  string         `yaml:"product"`
	Fixed    string         `yaml:"fixed"`
	Summary  string         `yaml:"summary"`
	Coverage string         `yaml:"coverage"`
	Rules    []advisoryRule `yaml:"rules"`
	Reason   string         `yaml:"reason"`
	Issue    int            `yaml:"issue"`
	Note     string         `yaml:"note"`
	Steps    []advisoryStep `yaml:"steps"`
}

const (
	advisoriesFile  = "../../docs/advisories.yml"
	advisoryDocs    = "../../docs/rules"
	advisoryFixture = "../../testdata/advisories"
	advisorySummary = 120 // keeps a summary one line on the website
)

// advisoryIDRe matches the ids a rule doc can cite.
var advisoryIDRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}`)

// advisoryRepoRe is the owner/name form of the repo key.
var advisoryRepoRe = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)

func loadAdvisories(t *testing.T) []advisory {
	t.Helper()
	f, err := os.Open(advisoriesFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var list []advisory
	if err := dec.Decode(&list); err != nil {
		t.Fatalf("%s: %v", advisoriesFile, err)
	}
	if len(list) == 0 {
		t.Fatal("no advisories")
	}
	return list
}

func isAdvisoryID(s string) bool { return advisoryIDRe.FindString(s) == s && s != "" }

// checkAdvisory returns what is wrong with one entry.
func checkAdvisory(a advisory, known map[string]bool) []string {
	var bad []string
	report := func(s string) { bad = append(bad, s) }
	if a.ID == "" || a.Product == "" || a.Summary == "" {
		report("id, product and summary are required")
	}
	if len([]rune(a.Summary)) > advisorySummary {
		report("summary is too long")
	}
	if !strings.HasSuffix(a.Summary, ".") {
		report("summary must be a sentence")
	}
	for _, alias := range a.Aliases {
		if !isAdvisoryID(alias) {
			report("alias " + alias + " is not a CVE or GHSA id")
		}
	}
	if a.Repo != "" && (!advisoryRepoRe.MatchString(a.Repo) || !slices.ContainsFunc(advisoryIDs(a), isGHSA)) {
		report("repo must be owner/name, on an entry with a GHSA")
	}
	bad = append(bad, checkAdvisoryKind(a)...)
	bad = append(bad, checkAdvisoryCoverage(a)...)
	bad = append(bad, checkAdvisoryReason(a.Reason, a.Issue, a.Note)...)
	listed := map[string]bool{}
	for _, r := range a.Rules {
		listed[r.Rule] = true
		if !known[r.Rule] {
			report("unknown rule " + r.Rule)
		}
		if !slices.Contains([]string{"error", "warn", "info"}, r.Severity) {
			report("severity of " + r.Rule + " must be error, warn or info")
		}
	}
	for _, s := range a.Steps {
		if s.Step == "" || len(s.Rules) == 0 && s.Reason == "" {
			report("a step needs a text and rules or a reason")
		}
		if s.Reason != "" && !slices.Contains([]string{"not-static", "no-rule-yet", "by-design"}, s.Reason) {
			report("bad step reason " + s.Reason)
		}
		for _, r := range s.Rules {
			if !listed[r] {
				report("step rule " + r + " is not in rules")
			}
		}
	}
	return bad
}

func isGHSA(id string) bool { return strings.HasPrefix(id, "GHSA-") }

func checkAdvisoryKind(a advisory) []string {
	switch a.Kind {
	case "cve", "analogue":
		if !isAdvisoryID(a.ID) {
			return []string{"a " + a.Kind + " entry needs a CVE or GHSA id"}
		}
		if len(a.Steps) > 0 {
			return []string{"steps belong to a campaign"}
		}
	case "campaign":
		if advisoryIDRe.MatchString(a.ID) {
			return []string{"a campaign is named, not numbered"}
		}
		if len(a.Steps) == 0 {
			return []string{"a campaign needs steps"}
		}
	default:
		return []string{"kind must be cve, analogue or campaign"}
	}
	return nil
}

func checkAdvisoryCoverage(a advisory) []string {
	switch a.Coverage {
	case "full":
		if len(a.Rules) == 0 {
			return []string{"coverage full needs rules"}
		}
		if a.Reason != "" {
			return []string{"coverage full takes no reason"}
		}
	case "partial":
		if len(a.Rules) == 0 || a.Reason == "" {
			return []string{"coverage partial needs rules and a reason"}
		}
	case "none":
		if len(a.Rules) != 0 {
			return []string{"coverage none takes no rules"}
		}
		if a.Reason == "" {
			return []string{"coverage none needs a reason"}
		}
	default:
		return []string{"coverage must be full, partial or none"}
	}
	return nil
}

func checkAdvisoryReason(reason string, issue int, note string) []string {
	switch reason {
	case "":
		if issue != 0 || note != "" {
			return []string{"issue and note need a reason"}
		}
	case "no-rule-yet":
		if issue == 0 {
			return []string{"no-rule-yet needs an issue"}
		}
	case "not-static", "by-design":
		if note == "" {
			return []string{reason + " needs a note"}
		}
	default:
		return []string{"reason must be not-static, no-rule-yet or by-design"}
	}
	return nil
}

func advisoryKnownRules() map[string]bool {
	known := map[string]bool{}
	for _, r := range rules.All() {
		known[r.ID()] = true
	}
	return known
}

func advisoryIDs(a advisory) []string { return append([]string{a.ID}, a.Aliases...) }

func advisoryOrder(a advisory) int {
	return slices.Index([]string{"cve", "analogue", "campaign"}, a.Kind)
}

func advisoryBefore(a, b advisory) bool {
	if a.Kind != b.Kind {
		return advisoryOrder(a) < advisoryOrder(b)
	}
	return a.ID < b.ID
}

func TestAdvisories_Structure(t *testing.T) {
	known := advisoryKnownRules()
	list := loadAdvisories(t)
	seen := map[string]bool{}
	for i, a := range list {
		for _, bad := range checkAdvisory(a, known) {
			t.Errorf("%s: %s", a.ID, bad)
		}
		for _, id := range advisoryIDs(a) {
			if seen[id] {
				t.Errorf("%s: id %s appears twice", a.ID, id)
			}
			seen[id] = true
		}
		if i > 0 && !advisoryBefore(list[i-1], a) {
			t.Errorf("%s: out of order, see the top of the file", a.ID)
		}
	}
}

// TestAdvisories_StructureCheck feeds checkAdvisory broken entries, so the
// structure test above cannot pass by accepting everything.
func TestAdvisories_StructureCheck(t *testing.T) {
	known := map[string]bool{"GL001": true}
	good := advisory{
		ID: "CVE-2026-1234", Kind: "cve", Product: "x", Summary: "A sentence.", Coverage: "full",
		Rules: []advisoryRule{{"GL001", "error"}},
	}
	if bad := checkAdvisory(good, known); len(bad) != 0 {
		t.Fatalf("good entry rejected: %v", bad)
	}
	campaign := func(a *advisory, steps ...advisoryStep) {
		a.ID, a.Kind, a.Steps = "Name", "campaign", steps
	}
	for name, breakIt := range map[string]func(a *advisory){
		"no product":     func(a *advisory) { a.Product = "" },
		"no summary":     func(a *advisory) { a.Summary = "" },
		"long summary":   func(a *advisory) { a.Summary = strings.Repeat("x", advisorySummary) + "." },
		"no sentence":    func(a *advisory) { a.Summary = "A summary" },
		"kind":           func(a *advisory) { a.Kind = "bug" },
		"bad id":         func(a *advisory) { a.ID = "CVE-1" },
		"analogue id":    func(a *advisory) { a.Kind, a.ID = "analogue", "Name" },
		"bad alias":      func(a *advisory) { a.Aliases = []string{"nope"} },
		"repo form":      func(a *advisory) { a.Repo, a.Aliases = "nope", []string{"GHSA-aaaa-bbbb-cccc"} },
		"repo no ghsa":   func(a *advisory) { a.Repo = "owner/name" },
		"coverage":       func(a *advisory) { a.Coverage = "most" },
		"full no rules":  func(a *advisory) { a.Rules = nil },
		"full reason":    func(a *advisory) { a.Reason, a.Note = "not-static", "n." },
		"partial no why": func(a *advisory) { a.Coverage = "partial" },
		"none rules":     func(a *advisory) { a.Coverage, a.Reason, a.Note = "none", "not-static", "n." },
		"none no why":    func(a *advisory) { a.Coverage, a.Rules = "none", nil },
		"unknown rule":   func(a *advisory) { a.Rules[0].Rule = "GL999" },
		"severity":       func(a *advisory) { a.Rules[0].Severity = "high" },
		"steps on cve":   func(a *advisory) { a.Steps = []advisoryStep{{Step: "s", Reason: "not-static"}} },
		"no issue":       func(a *advisory) { a.Coverage, a.Rules, a.Reason = "none", nil, "no-rule-yet" },
		"no note":        func(a *advisory) { a.Coverage, a.Rules, a.Reason = "none", nil, "by-design" },
		"bad reason":     func(a *advisory) { a.Coverage, a.Rules, a.Reason = "none", nil, "later" },
		"stray note":     func(a *advisory) { a.Note = "n." },
		"no steps":       func(a *advisory) { campaign(a) },
		"numbered campaign": func(a *advisory) {
			campaign(a, advisoryStep{Step: "s", Rules: []string{"GL001"}})
			a.ID = "CVE-2026-1234"
		},
		"empty step":      func(a *advisory) { campaign(a, advisoryStep{Step: "s"}) },
		"bad step reason": func(a *advisory) { campaign(a, advisoryStep{Step: "s", Reason: "later"}) },
		"step rule":       func(a *advisory) { campaign(a, advisoryStep{Step: "s", Rules: []string{"GL999"}}) },
	} {
		a := good
		a.Rules = slices.Clone(good.Rules)
		breakIt(&a)
		if bad := checkAdvisory(a, known); len(bad) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func advisorySlug(id string) string {
	return strings.ToLower(strings.ReplaceAll(id, " ", "-")) + ".yml"
}

// TestAdvisories_Fixtures scans each fixture and requires every listed rule at
// exactly the listed severity. Other rules may fire as well: GL053 fires on
// nearly every minimal pipeline, and the list only claims the listed ones.
func TestAdvisories_Fixtures(t *testing.T) {
	used := map[string]bool{}
	for _, a := range loadAdvisories(t) {
		name := advisorySlug(a.ID)
		path := filepath.Join(advisoryFixture, name)
		if len(a.Rules) == 0 {
			if _, err := os.Stat(path); err == nil {
				t.Errorf("%s: an entry without rules has no fixture", a.ID)
			}
			continue
		}
		used[name] = true
		content, err := os.ReadFile(path) // #nosec G304 -- fixture in this repository
		if err != nil {
			t.Errorf("%s: %v", a.ID, err)
			continue
		}
		t.Run(a.ID, func(t *testing.T) {
			_, out, stderr := runCLI(t, map[string]string{".gitlab-ci.yml": string(content)}, "--format", "json")
			var report struct {
				Findings []struct {
					Rule     string `json:"rule"`
					Severity string `json:"severity"`
				} `json:"findings"`
			}
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("%v: %s %s", err, out, stderr)
			}
			got := map[advisoryRule]bool{}
			for _, f := range report.Findings {
				got[advisoryRule{f.Rule, f.Severity}] = true
			}
			for _, r := range a.Rules {
				if !got[r] {
					t.Errorf("%s did not report %s, got %v", r.Rule, r.Severity, got)
				}
			}
		})
	}
	entries, err := os.ReadDir(advisoryFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !used[e.Name()] {
			t.Errorf("%s: no advisory uses this fixture", e.Name())
		}
	}
}

// TestAdvisories_RuleDocs links the list and the rule docs in both directions.
// Campaigns have no id a doc could cite, so they are left out.
func TestAdvisories_RuleDocs(t *testing.T) {
	docs, err := filepath.Glob(filepath.Join(advisoryDocs, "GL*.md"))
	if err != nil || len(docs) == 0 {
		t.Fatalf("no rule docs: %v", err)
	}
	text := map[string]string{}
	for _, doc := range docs {
		b, err := os.ReadFile(doc) // #nosec G304 -- rule docs in this repository
		if err != nil {
			t.Fatal(err)
		}
		text[strings.TrimSuffix(filepath.Base(doc), ".md")] = string(b)
	}
	names := map[string]map[string]bool{} // id to the rules its entry names
	for _, a := range loadAdvisories(t) {
		if a.Kind == "campaign" {
			continue
		}
		named := map[string]bool{}
		for _, r := range a.Rules {
			named[r.Rule] = true
			if !slices.ContainsFunc(advisoryIDs(a), func(id string) bool {
				return strings.Contains(text[r.Rule], id)
			}) {
				t.Errorf("%s names %s, but docs/rules/%s.md does not cite it", a.ID, r.Rule, r.Rule)
			}
		}
		for _, id := range advisoryIDs(a) {
			names[id] = named
		}
	}
	for doc, content := range text {
		for _, id := range advisoryIDRe.FindAllString(content, -1) {
			named, ok := names[id]
			if !ok {
				t.Errorf("docs/rules/%s.md cites %s, which is not in docs/advisories.yml", doc, id)
			} else if !named[doc] {
				t.Errorf("docs/rules/%s.md cites %s, but its entry does not name %s", doc, id, doc)
			}
		}
	}
}
