package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glsec/glsec/internal/finding"
)

func parseStr(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	return cfg
}

func TestDefault(t *testing.T) {
	cfg := Default()
	if !cfg.RuleEnabled("GL001") {
		t.Error("GL001 should be enabled by default")
	}
	if !cfg.AboveMinSeverity(finding.Finding{Severity: finding.Info}) {
		t.Error("info should pass with no min-severity set")
	}
}

func TestLoad_MissingDefaultFile(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	cfg, err := Load(DefaultFile)
	if err != nil {
		t.Fatalf("expected no error for missing default config: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoad_ExplicitMissing(t *testing.T) {
	_, err := Load("/nonexistent/.glsec.yml")
	if err == nil {
		t.Error("expected error for missing explicit config path")
	}
}

func TestParse_RuleOff(t *testing.T) {
	cfg := parseStr(t, `
rules:
  GL001: off
  GL002: warn
`)
	if cfg.RuleEnabled("GL001") {
		t.Error("GL001 should be disabled")
	}
	if !cfg.RuleEnabled("GL002") {
		t.Error("GL002 should be enabled")
	}
	if !cfg.RuleEnabled("GL003") {
		t.Error("GL003 not in config — should be enabled")
	}
}

func TestParse_SeverityOverride_Flat(t *testing.T) {
	cfg := parseStr(t, `rules:
  GL001: warn
`)
	f := finding.Finding{RuleID: "GL001", Severity: finding.Error}
	got := cfg.ApplySeverity(f)
	if got.Severity != finding.Warn {
		t.Errorf("expected warn, got %s", got.Severity)
	}
}

func TestParse_SeverityOverride_Nested(t *testing.T) {
	cfg := parseStr(t, `
rules:
  GL001:
    severity: warn
  GL011:
    severity: error
`)
	f1 := finding.Finding{RuleID: "GL001", Severity: finding.Error}
	if got := cfg.ApplySeverity(f1); got.Severity != finding.Warn {
		t.Errorf("GL001: expected warn, got %s", got.Severity)
	}
	f2 := finding.Finding{RuleID: "GL011", Severity: finding.Warn}
	if got := cfg.ApplySeverity(f2); got.Severity != finding.Error {
		t.Errorf("GL011: expected error, got %s", got.Severity)
	}
}

func TestParse_SeverityOverride_Nested_Off(t *testing.T) {
	cfg := parseStr(t, `
rules:
  GL001:
    severity: off
`)
	if cfg.RuleEnabled("GL001") {
		t.Error("GL001 should be disabled via nested severity: off")
	}
}

func TestParse_SeverityOverride_Nested_UnknownKey(t *testing.T) {
	_, err := parse([]byte("rules:\n  GL001:\n    severity: warn\n    unknown: value\n"), "test.yml")
	if err == nil {
		t.Error("expected error for unknown key inside rule config mapping")
	}
}

func TestParse_SeverityOverride_Nested_InvalidSeverity(t *testing.T) {
	_, err := parse([]byte("rules:\n  GL001:\n    severity: critical\n"), "test.yml")
	if err == nil {
		t.Error("expected error for invalid severity in nested form")
	}
}

func TestParse_MinSeverity(t *testing.T) {
	cfg := parseStr(t, `min-severity: error`)
	if cfg.AboveMinSeverity(finding.Finding{Severity: finding.Warn}) {
		t.Error("warn should be filtered by min-severity: error")
	}
	if !cfg.AboveMinSeverity(finding.Finding{Severity: finding.Error}) {
		t.Error("error should pass min-severity: error")
	}
}

func TestParse_UnknownKey(t *testing.T) {
	_, err := parse([]byte("unknown-key: value\n"), "test.yml")
	if err == nil {
		t.Error("expected error for unknown top-level key")
	}
}

func TestParse_InvalidRuleID(t *testing.T) {
	_, err := parse([]byte("rules:\n  BADID: off\n"), "test.yml")
	if err == nil {
		t.Error("expected error for invalid rule ID")
	}
}

func TestParse_InvalidSeverity(t *testing.T) {
	_, err := parse([]byte("rules:\n  GL001: critical\n"), "test.yml")
	if err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestParse_InvalidMinSeverity(t *testing.T) {
	_, err := parse([]byte("min-severity: off\n"), "test.yml")
	if err == nil {
		t.Error("expected error for min-severity: off")
	}
}

func TestParse_Empty(t *testing.T) {
	cfg, err := parse([]byte(""), "test.yml")
	if err != nil {
		t.Fatalf("empty config should be valid: %v", err)
	}
	if !cfg.RuleEnabled("GL001") {
		t.Error("empty config should enable all rules")
	}
}

func TestParse_GitLabVersion_Valid(t *testing.T) {
	cfg := parseStr(t, `gitlab-version: "16.0"`)
	if cfg.GitLabVersion != "16.0" {
		t.Errorf("expected 16.0, got %q", cfg.GitLabVersion)
	}
}

func TestParse_GitLabVersion_Invalid(t *testing.T) {
	_, err := parse([]byte("gitlab-version: abc\n"), "test.yml")
	if err == nil {
		t.Error("expected error for invalid gitlab-version")
	}
}

func TestParse_GitLabVersion_Absent(t *testing.T) {
	cfg := parseStr(t, `min-severity: warn`)
	if cfg.GitLabVersion != "" {
		t.Errorf("expected empty gitlab-version, got %q", cfg.GitLabVersion)
	}
}

func TestParse_Strict(t *testing.T) {
	cfg := parseStr(t, `strict: true`)
	if !cfg.Strict {
		t.Error("expected Strict to be true")
	}
}

func TestParse_NoExitCodes(t *testing.T) {
	cfg := parseStr(t, `no-exit-codes: true`)
	if !cfg.NoExitCodes {
		t.Error("expected NoExitCodes to be true")
	}
}

func TestParse_ExcludePaths(t *testing.T) {
	cfg := parseStr(t, `
exclude_paths:
  - legacy/.gitlab-ci.yml
  - vendor/
`)
	if len(cfg.ExcludePaths) != 2 {
		t.Fatalf("expected 2 exclude paths, got %d", len(cfg.ExcludePaths))
	}
	if cfg.ExcludePaths[0] != "legacy/.gitlab-ci.yml" {
		t.Errorf("unexpected first path: %q", cfg.ExcludePaths[0])
	}
}

func TestParse_StrictAndNoExitCodes_UnknownKey(t *testing.T) {
	_, err := parse([]byte("strictmode: true\n"), "test.yml")
	if err == nil {
		t.Error("expected error for unknown top-level key 'strictmode'")
	}
}

func TestLoad_FromFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("rules:\n  GL001: off\nmin-severity: warn\n")
	path := filepath.Join(dir, ".glsec.yml")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RuleEnabled("GL001") {
		t.Error("GL001 should be off")
	}
	if cfg.MinSeverity != "warn" {
		t.Errorf("expected min-severity warn, got %q", cfg.MinSeverity)
	}
}

func TestOWASPEnabled_Allowlist(t *testing.T) {
	cfg := parseStr(t, `
owasp:
  - CICD-SEC-6
`)
	if !cfg.OWASPEnabled([]string{"CICD-SEC-6"}) {
		t.Error("CICD-SEC-6 should be enabled when in allowlist")
	}
	if cfg.OWASPEnabled([]string{"CICD-SEC-3"}) {
		t.Error("CICD-SEC-3 should be disabled when not in allowlist")
	}
	if !cfg.OWASPEnabled([]string{"CICD-SEC-3", "CICD-SEC-6"}) {
		t.Error("rule with multiple categories should pass if any is in allowlist")
	}
}

func TestOWASPEnabled_Denylist(t *testing.T) {
	cfg := parseStr(t, `
owasp_exclude:
  - CICD-SEC-7
`)
	if cfg.OWASPEnabled([]string{"CICD-SEC-7"}) {
		t.Error("CICD-SEC-7 should be disabled when in denylist")
	}
	if !cfg.OWASPEnabled([]string{"CICD-SEC-6"}) {
		t.Error("CICD-SEC-6 should be enabled when not in denylist")
	}
}

func TestOWASPEnabled_Empty(t *testing.T) {
	cfg := Default()
	if !cfg.OWASPEnabled([]string{"CICD-SEC-6"}) {
		t.Error("all categories should be enabled with no filter set")
	}
	if !cfg.OWASPEnabled(nil) {
		t.Error("rule with no category should be enabled with no filter set")
	}
}

func TestOWASPEnabled_AllowlistWithNoCategory(t *testing.T) {
	cfg := parseStr(t, `
owasp:
  - CICD-SEC-6
`)
	if cfg.OWASPEnabled(nil) {
		t.Error("rule with no category should be excluded when allowlist is set")
	}
}

func TestParse_InvalidOWASPCategory(t *testing.T) {
	_, err := parse([]byte(`
owasp:
  - CICD-SEC-99
`), "test.yml")
	if err == nil {
		t.Error("expected error for invalid OWASP category")
	}
}

func TestRequireIgnoreReason(t *testing.T) {
	cfg, err := parse([]byte("require_ignore_reason: true\n"), ".glsec.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.RequireIgnoreReason {
		t.Error("require_ignore_reason should be parsed from the config file")
	}
	// Absent means off, so existing configs keep their behaviour.
	def, err := parse([]byte("strict: true\n"), ".glsec.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if def.RequireIgnoreReason {
		t.Error("require_ignore_reason must default to false")
	}
}
