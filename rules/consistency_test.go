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
	if len(OWASPCategories(id)) == 0 {
		t.Errorf("no OWASP category mapping for %s (add to rules/owasp.go)", id)
	}
}

func checkCWEMapping(t *testing.T, id string) {
	t.Helper()
	if CWEID(id) == "" {
		t.Errorf("no CWE mapping for %s (add to rules/cwe.go)", id)
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
