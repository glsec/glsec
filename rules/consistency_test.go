package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var ruleIDPattern = regexp.MustCompile(`^GL\d{3}$`)

func TestRuleConsistency(t *testing.T) {
	rulesOverview := loadRulesOverview(t)

	for _, r := range All() {
		r := r
		t.Run(r.ID(), func(t *testing.T) {
			id := r.ID()

			if !ruleIDPattern.MatchString(id) {
				t.Errorf("ID %q does not match GL### format", id)
			}

			checkDocFile(t, id)
			checkFixture(t, id)
			checkOWASPMapping(t, id)
			checkCWEMapping(t, id)
			checkRulesOverview(t, id, rulesOverview)
		})
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

func checkFixture(t *testing.T, id string) {
	t.Helper()
	prefix := strings.ToLower(id) + "-"
	matches, err := filepath.Glob(filepath.Join("..", "testdata", "fixtures", prefix+"*.yml"))
	if err != nil {
		t.Fatalf("glob error: %v", err)
	}
	if len(matches) == 0 {
		t.Errorf("no fixture in testdata/fixtures/ matching %s*.yml", prefix)
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

func checkRulesOverview(t *testing.T, id, overview string) {
	t.Helper()
	if !strings.Contains(overview, id) {
		t.Errorf("%s is not listed in docs/rules.md", id)
	}
}
