package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

var ruleIDPattern = regexp.MustCompile(`^GL\d{3}$`)

func TestRuleConsistency(t *testing.T) {
	checkNoDuplicateIDs(t)
	checkCWENamesComplete(t)

	rulesOverview := loadRulesOverview(t)

	for _, r := range All() {
		r := r
		t.Run(r.ID(), func(t *testing.T) {
			id := r.ID()

			if !ruleIDPattern.MatchString(id) {
				t.Errorf("ID %q does not match GL### format", id)
			}

			checkDocFile(t, id)
			checkFixtureFires(t, id)
			checkOWASPMapping(t, id)
			checkCWEMapping(t, id)
			checkRulesOverviewLink(t, id, rulesOverview)
			checkRulesOverviewSection(t, id, rulesOverview, OWASPCategories(id))
		})
	}
}

func checkNoDuplicateIDs(t *testing.T) {
	t.Helper()
	seen := map[string]bool{}
	for _, r := range All() {
		if seen[r.ID()] {
			t.Errorf("duplicate rule ID %q in All()", r.ID())
		}
		seen[r.ID()] = true
	}
}

func checkDocFile(t *testing.T, id string) {
	t.Helper()
	path := filepath.Join("..", "docs", "rules", id+".md")
	content, err := os.ReadFile(path) //nolint:gosec // G304: test reads known-safe local paths
	if err != nil {
		t.Errorf("missing docs/rules/%s.md", id)
		return
	}
	if !strings.Contains(string(content), "CICD-SEC-") && !strings.Contains(string(content), "OWASP") {
		t.Errorf("docs/rules/%s.md has no OWASP reference (add 'CICD-SEC-N' or 'OWASP')", id)
	}
}

func checkFixtureFires(t *testing.T, id string) {
	t.Helper()
	prefix := strings.ToLower(id) + "-"
	matches, err := filepath.Glob(filepath.Join("..", "testdata", "fixtures", prefix+"*.yml"))
	if err != nil {
		t.Fatalf("glob error: %v", err)
	}
	if len(matches) == 0 {
		t.Errorf("no fixture in testdata/fixtures/ matching %s*.yml", prefix)
		return
	}

	var rule interface {
		ID() string
	}
	for _, r := range All() {
		if r.ID() == id {
			rule = r
			break
		}
	}

	totalFindings := 0
	for _, path := range matches {
		doc, parseErr := parser.ParseFile(path)
		if parseErr != nil {
			t.Errorf("fixture %s failed to parse: %v", filepath.Base(path), parseErr)
			continue
		}
		for _, r := range All() {
			if r.ID() == rule.ID() {
				totalFindings += len(r.Check(doc.Root, path))
				break
			}
		}
	}
	if totalFindings == 0 {
		t.Errorf("fixture(s) for %s produce no findings — fixture must trigger the rule", id)
	}
}

func checkOWASPMapping(t *testing.T, id string) {
	t.Helper()
	cats := OWASPCategories(id)
	if len(cats) == 0 {
		t.Errorf("no OWASP category mapping for %s (add to rules/owasp.go)", id)
		return
	}
	checkDocOWASPMatchesMap(t, id, cats)
}

var owaspLineURLPat = regexp.MustCompile(`\]\([^)]*\)`)
var owaspCatPat = regexp.MustCompile(`CICD-SEC-([1-9][0-9]?)\b`)

func checkDocOWASPMatchesMap(t *testing.T, id string, expected []string) {
	t.Helper()
	path := filepath.Join("..", "docs", "rules", id+".md")
	content, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return // missing doc is already caught by checkDocFile
	}
	owaspLine := ""
	for _, l := range strings.Split(string(content), "\n") {
		if strings.Contains(l, "**OWASP:**") {
			owaspLine = l
			break
		}
	}
	if owaspLine == "" {
		t.Errorf("%s: no **OWASP:** line in doc", id)
		return
	}
	// Strip URL portions so CICD-SEC-06 in a URL doesn't count as a category.
	stripped := owaspLineURLPat.ReplaceAllString(owaspLine, "")
	var got []string
	for _, m := range owaspCatPat.FindAllStringSubmatch(stripped, -1) {
		got = append(got, fmt.Sprintf("CICD-SEC-%s", m[1]))
	}
	if fmt.Sprint(got) != fmt.Sprint(expected) {
		t.Errorf("%s: doc OWASP %v does not match owasp.go map %v", id, got, expected)
	}
}

func checkRulesOverviewSection(t *testing.T, id string, overview string, expected []string) {
	t.Helper()
	// Find the section header line(s) that this rule's link falls under.
	// A section starts with "## " and contains a CICD-SEC-N link.
	sectionCatPat := regexp.MustCompile(`\[CICD-SEC-([1-9][0-9]?)\]`)
	ruleLink := fmt.Sprintf("[%s](rules/%s.md)", id, id)
	lines := strings.Split(overview, "\n")
	var currentCats []string
	for _, l := range lines {
		if strings.HasPrefix(l, "## ") {
			currentCats = nil
			for _, m := range sectionCatPat.FindAllStringSubmatch(l, -1) {
				currentCats = append(currentCats, fmt.Sprintf("CICD-SEC-%s", m[1]))
			}
		}
		if strings.Contains(l, ruleLink) {
			for _, cat := range expected {
				found := false
				for _, sc := range currentCats {
					if sc == cat {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: in rules.md section %v but owasp.go map says %v", id, currentCats, expected)
				}
			}
			return
		}
	}
}

func checkCWEMapping(t *testing.T, id string) {
	t.Helper()
	cweID := CWEID(id)
	if cweID == "" {
		t.Errorf("no CWE mapping for %s (add to rules/cwe.go)", id)
		return
	}
	if CWEName(cweID) == "" {
		t.Errorf("CWE %s for %s has no name entry in cweNames (add to rules/cwe.go)", cweID, id)
	}
}

// checkCWENamesComplete verifies every CWE ID referenced in cweIDs has a name in cweNames.
func checkCWENamesComplete(t *testing.T) {
	t.Helper()
	for _, r := range All() {
		cweID := CWEID(r.ID())
		if cweID == "" {
			continue
		}
		if CWEName(cweID) == "" {
			t.Errorf("CWE %s (used by %s) has no name in cweNames map (add to rules/cwe.go)", cweID, r.ID())
		}
	}
}

func loadRulesOverview(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "docs", "rules.md"))
	if err != nil {
		t.Fatalf("could not read docs/rules.md: %v", err)
	}
	return string(data)
}

func checkRulesOverviewLink(t *testing.T, id, overview string) {
	t.Helper()
	link := fmt.Sprintf("[%s](rules/%s.md)", id, id)
	if !strings.Contains(overview, link) {
		t.Errorf("%s has no proper link in docs/rules.md (expected %q)", id, link)
	}
}

// TestReadmeRuleTable verifies the README "Rules" category table stays in sync
// with the registered rules and their owasp.go category mappings — a table
// that is otherwise hand-maintained and prone to drift.
func TestReadmeRuleTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readme := string(data)

	// Rule count: "N rules across ..." must equal the registered rule count.
	countPat := regexp.MustCompile(`(?m)^(\d+) rules across`)
	cm := countPat.FindStringSubmatch(readme)
	if cm == nil {
		t.Fatal("could not find 'N rules across' line in README")
	}
	want := len(All())
	if cm[1] != fmt.Sprint(want) {
		t.Errorf("README says %s rules, but %d are registered", cm[1], want)
	}

	// Category table rows: "| name | CICD-SEC-... | GL..., ... |".
	rowPat := regexp.MustCompile(`(?m)^\|[^|]+\|([^|]*CICD-SEC[^|]*)\|([^|]+)\|\s*$`)
	catPat := regexp.MustCompile(`CICD-SEC-\d+`)
	idPat := regexp.MustCompile(`GL\d{3}`)

	rows := rowPat.FindAllStringSubmatch(readme, -1)
	if len(rows) == 0 {
		t.Fatal("no category rows found in README rule table")
	}

	seen := map[string]int{}
	for _, row := range rows {
		rowCats := map[string]bool{}
		for _, c := range catPat.FindAllString(row[1], -1) {
			rowCats[c] = true
		}
		for _, id := range idPat.FindAllString(row[2], -1) {
			seen[id]++
			cats := OWASPCategories(id)
			matched := false
			for _, c := range cats {
				if rowCats[c] {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("README lists %s under categories %v, but owasp.go maps it to %v", id, keysOf(rowCats), cats)
			}
		}
	}

	for _, r := range All() {
		switch seen[r.ID()] {
		case 0:
			t.Errorf("%s is registered but missing from the README rule table", r.ID())
		case 1:
		default:
			t.Errorf("%s appears %d times in the README rule table (want 1)", r.ID(), seen[r.ID()])
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
