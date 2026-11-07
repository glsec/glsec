// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
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

func TestRequireImageDigest(t *testing.T) {
	if Default().RequireImageDigest {
		t.Fatal("digest policy must be opt-in")
	}
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{"require_image_digest: true", true},
		{"require_image_digest: false", false},
		{"{}", false},
	} {
		if got := parseStr(t, tc.src).RequireImageDigest; got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.src, got, tc.want)
		}
	}
	for _, src := range []string{"require_image_digest: not-a-bool", "require_image_digest: [true]"} {
		if _, err := parse([]byte(src), "test.yml"); err == nil {
			t.Errorf("accepted invalid boolean: %s", src)
		}
	}
}

func TestRequireIncludeSHA(t *testing.T) {
	if Default().RequireIncludeSHA {
		t.Fatal("include policy must be opt-in")
	}
	if !parseStr(t, "require_include_sha: true").RequireIncludeSHA {
		t.Error("require_include_sha: true not read")
	}
	if _, err := parse([]byte("require_include_sha: not-a-bool"), "test.yml"); err == nil {
		t.Error("accepted invalid boolean")
	}
}

func TestLoad_MissingDefaultFile(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(orig) }()

	cfg, err := LoadDefault()
	if err != nil {
		t.Fatalf("expected no error for missing default config: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if _, err := Load(DefaultFile); err == nil {
		t.Error("a file asked for by name must exist, also when it has the default name")
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

func TestLoad_InvalidConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		src  string
		want string
	}{
		{"invalid YAML", "rules: [\n", "yaml:"},
		{"top-level list", "- rules\n", "config must be a YAML mapping"},
		{"top-level string", "not a mapping\n", "config must be a YAML mapping"},
		{"rule override list", "rules:\n  GL001: [warn]\n", "rule config must be a string or mapping"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".glsec.yml")
			if err := os.WriteFile(path, []byte(tt.src), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if err == nil {
				t.Fatal("expected invalid config to fail")
			}
			if cfg != nil {
				t.Errorf("expected nil config, got %+v", cfg)
			}
			if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("expected config path and %q in error, got %v", tt.want, err)
			}
		})
	}
}

func TestRuleEnabled_CLISelection(t *testing.T) {
	for _, tt := range []struct {
		name string
		only map[string]bool
		skip map[string]bool
		want [3]bool
	}{
		{name: "file defaults", want: [3]bool{true, false, true}},
		{name: "only includes enabled rule", only: map[string]bool{"GL001": true}, want: [3]bool{true, false, false}},
		{name: "only keeps file-disabled rule off", only: map[string]bool{"GL002": true}, want: [3]bool{false, false, false}},
		{name: "only includes rule without override", only: map[string]bool{"GL003": true}, want: [3]bool{false, false, true}},
		{name: "skip overrides enabled file rule", skip: map[string]bool{"GL001": true}, want: [3]bool{false, false, true}},
		{name: "skip disables rule without override", skip: map[string]bool{"GL003": true}, want: [3]bool{true, false, false}},
		{name: "skip wins over only", only: map[string]bool{"GL001": true, "GL003": true}, skip: map[string]bool{"GL001": true}, want: [3]bool{false, false, true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := parseStr(t, "rules:\n  GL001: warn\n  GL002: off\n")
			cfg.Only, cfg.Skip = tt.only, tt.skip
			for i, id := range []string{"GL001", "GL002", "GL003"} {
				if got := cfg.RuleEnabled(id); got != tt.want[i] {
					t.Errorf("RuleEnabled(%q) = %v, want %v", id, got, tt.want[i])
				}
			}
		})
	}
}

func TestApplySeverity_Unchanged(t *testing.T) {
	cfg := parseStr(t, "rules:\n  GL001: off\n")
	for _, id := range []string{"GL001", "GL002"} {
		t.Run(id, func(t *testing.T) {
			f := finding.Finding{
				RuleID: id, Severity: finding.Warn, Job: "build",
				Message: "test finding", File: "test.yml", Line: 3, Col: 5,
			}
			if got := cfg.ApplySeverity(f); got != f {
				t.Errorf("ApplySeverity changed finding: got %+v, want %+v", got, f)
			}
		})
	}
}

func TestParse_ShellCheckKeys(t *testing.T) {
	for _, tc := range []struct {
		name, src, wantErr string
	}{
		{"known keys", "shellcheck:\n  enabled: true\n  path: /bin/shellcheck\n", ""},
		{"misspelt", "strict: false\nshellcheck:\n  enabeld: true\n", `.glsec.yml:3: unknown config key "shellcheck.enabeld"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse([]byte(tc.src), DefaultFile)
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
				t.Fatalf("err = %v, want %s", err, tc.wantErr)
			}
		})
	}
}
