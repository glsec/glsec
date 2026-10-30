// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings008(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL008.Check(doc.Root, "test.yml")
}

func TestGL008_AllowFailure_Warn(t *testing.T) {
	f := findings008(t, `
dast:
  allow_failure: true
  variables:
    DAST_WEBSITE: "https://example.com"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

// The templates already set allow_failure: true on these jobs, so a pipeline
// that repeats it is not doing anything new and must not be reported.
func TestGL008_TemplateAllowFailure_NoFinding(t *testing.T) {
	for _, job := range []string{
		"secret_detection",
		"container_scanning",
		"iac-sast",
		"kics-iac-sast",
		"semgrep-sast",
		"gitlab-advanced-sast",
		"gosec-sast",
		"spotbugs-sast",
		"gemnasium-dependency_scanning",
	} {
		f := findings008(t, job+":\n  allow_failure: true\n")
		if len(f) != 0 {
			t.Errorf("%s: expected no finding for template-defaulted allow_failure, got %d", job, len(f))
		}
	}
}

// sast and dependency_scanning are configuration-only: the templates give them
// `rules: - when: never` and a script that exits 1, and the analyzers inherit
// from them through .sast-analyzer / .ds-analyzer. Neither an allow_failure
// nor a disabling rule on them changes anything, so neither is reported.
func TestGL008_ConfigurationOnlyJobs_NoFinding(t *testing.T) {
	cases := []struct {
		job  string
		yaml string
	}{
		{"sast", "sast:\n  allow_failure: true\n"},
		{"dependency_scanning", "dependency_scanning:\n  allow_failure: true\n"},
		{"sast", "sast:\n  rules:\n    - when: never\n"},
		{"dependency_scanning", "dependency_scanning:\n  rules:\n    - when: never\n"},
		{"sast", "sast:\n  rules:\n    - when: manual\n"},
		{"dependency_scanning", "dependency_scanning:\n  rules:\n    - when: manual\n"},
		{"sast", "sast:\n  when: manual\n"},
		{"dependency_scanning", "dependency_scanning:\n  when: manual\n"},
	}
	for _, c := range cases {
		f := findings008(t, c.yaml)
		if len(f) != 0 {
			t.Errorf("%s: expected no finding on a configuration-only job, got %d", c.job, len(f))
		}
	}
}

// The exemption must not silently drop every check for a job that does run.
func TestGL008_ConfigurationOnlyJobsAreScanJobs(t *testing.T) {
	for job := range configurationOnlyJobs {
		if !securityScanJobs[job] {
			t.Errorf("%s is treated as configuration-only but is not a scan job", job)
		}
		if templateAllowFailureJobs[job] {
			t.Errorf("%s is treated as configuration-only but is also exempted from the allow_failure check", job)
		}
	}
}

// The analyzer jobs are the ones that actually scan; switching one off goes
// unnoticed without this.
func TestGL008_AnalyzerJobDisabled_Warn(t *testing.T) {
	cases := []struct {
		job  string
		yaml string
	}{
		{"semgrep-sast", "semgrep-sast:\n  rules:\n    - when: never\n"},
		{"gitlab-advanced-sast", "gitlab-advanced-sast:\n  rules:\n    - when: never\n"},
		{"gosec-sast", "gosec-sast:\n  rules:\n    - when: manual\n"},
		{"spotbugs-sast", "spotbugs-sast:\n  when: manual\n"},
		{"gemnasium-dependency_scanning", "gemnasium-dependency_scanning:\n  rules:\n    - when: never\n"},
		{"iac-sast", "iac-sast:\n  rules:\n    - when: never\n"},
		{"kics-iac-sast", "kics-iac-sast:\n  when: manual\n"},
	}
	for _, c := range cases {
		f := findings008(t, c.yaml)
		if len(f) != 1 {
			t.Errorf("%s: expected 1 finding, got %d", c.job, len(f))
			continue
		}
		if f[0].Job != c.job {
			t.Errorf("expected job attribution %q, got %q", c.job, f[0].Job)
		}
	}
}

// sast-iac is the template file, not a job; the jobs it creates are iac-sast
// and kics-iac-sast.
func TestGL008_SastIacIsNotAJob_NoFinding(t *testing.T) {
	f := findings008(t, `
sast-iac:
  allow_failure: true
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for sast-iac, got %d", len(f))
	}
	f = findings008(t, `
sast-iac:
  rules:
    - when: never
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a disabled sast-iac, got %d", len(f))
	}
}

// An exempted job must stay a scan job, or the exemption would silently drop
// every check for it.
func TestGL008_TemplateAllowFailureJobsAreScanJobs(t *testing.T) {
	for job := range templateAllowFailureJobs {
		if !securityScanJobs[job] {
			t.Errorf("%s is exempted from the allow_failure check but is not a scan job", job)
		}
	}
}

func TestGL008_AllowFailureFalse_NoFinding(t *testing.T) {
	f := findings008(t, `
dast:
  allow_failure: false
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when allow_failure: false, got %d", len(f))
	}
}

func TestGL008_NoAllowFailure_NoFinding(t *testing.T) {
	f := findings008(t, `
dast:
  variables:
    DAST_WEBSITE: "https://example.com"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when allow_failure is absent, got %d", len(f))
	}
}

func TestGL008_NonSecurityJob_NoFinding(t *testing.T) {
	f := findings008(t, `
build:
  allow_failure: true
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-security job, got %d", len(f))
	}
}

func TestGL008_AllowFailureExitCodes_NoFinding(t *testing.T) {
	// allow_failure: {exit_codes: [...]} is intentional and not the same as allow_failure: true
	f := findings008(t, `
dast:
  allow_failure:
    exit_codes: [1]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for exit_codes form, got %d", len(f))
	}
}

func TestGL008_MultipleJobs(t *testing.T) {
	f := findings008(t, `
dast:
  allow_failure: true

api_fuzzing:
  allow_failure: true

build:
  allow_failure: true
  script: [make]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (dast + api_fuzzing), got %d", len(f))
	}
}

func TestGL008_LineNumber(t *testing.T) {
	f := findings008(t, `
dast:
  allow_failure: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL008_WhenManual_Warn(t *testing.T) {
	f := findings008(t, `
dast:
  when: manual
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for when: manual, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if f[0].Job != "dast" {
		t.Errorf("expected job attribution %q, got %q", "dast", f[0].Job)
	}
}

func TestGL008_WhenOnSuccess_NoFinding(t *testing.T) {
	f := findings008(t, `
dast:
  when: on_success
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for when: on_success, got %d", len(f))
	}
}

func TestGL008_SoleUnconditionalNeverRule_Warn(t *testing.T) {
	f := findings008(t, `
secret_detection:
  rules:
    - when: never
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for rules: [when: never], got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "every context") {
		t.Errorf("unexpected message: %q", f[0].Message)
	}
}

func TestGL008_SoleUnconditionalManualRule_Warn(t *testing.T) {
	f := findings008(t, `
dast:
  rules:
    - when: manual
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for rules: [when: manual], got %d", len(f))
	}
}

// The kill-switch guard GitLab's own templates ship is conditional, and keeping
// it in an override is idiomatic. Flagging it would be a false positive; the
// dangerous half — setting the variable — is GL082's job.
func TestGL008_ConditionalNeverRule_NoFinding(t *testing.T) {
	f := findings008(t, `
secret_detection:
  rules:
    - if: $SECRET_DETECTION_DISABLED
      when: never
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a conditional when: never, got %d", len(f))
	}
}

// "Run on merge requests, otherwise don't" is scoping, not disabling.
func TestGL008_TrailingNeverCatchAll_NoFinding(t *testing.T) {
	f := findings008(t, `
dast:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - when: never
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a trailing catch-all, got %d", len(f))
	}
}

func TestGL008_SoleRuleWithChangesOrExists_NoFinding(t *testing.T) {
	for _, cond := range []string{
		"changes: [\"**/*.go\"]",
		"exists: [\"go.mod\"]",
	} {
		f := findings008(t, "dast:\n  rules:\n    - "+cond+"\n      when: never\n")
		if len(f) != 0 {
			t.Errorf("expected no finding for a rule gated on %s, got %d", cond, len(f))
		}
	}
}

func TestGL008_NonSecurityJobManual_NoFinding(t *testing.T) {
	f := findings008(t, `
deploy:
  when: manual
  rules:
    - when: never
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for a non-security job, got %d", len(f))
	}
}

func TestGL008_AllowFailureAndManual_BothReported(t *testing.T) {
	f := findings008(t, `
dast:
  allow_failure: true
  when: manual
`)
	if len(f) != 2 {
		t.Fatalf("expected both findings, got %d", len(f))
	}
}

// A scan job switched off under its template name but run by a job that
// extends it keeps scanning (#1000).
func TestGL008_RunByExtendingJob(t *testing.T) {
	const base = "include:\n  - template: Jobs/Secret-Detection.gitlab-ci.yml\nsecret_detection:\n  rules:\n    - when: never\n"
	for child, want := range map[string]int{
		"secrets-scan:\n  extends: secret_detection\n  stage: test\n  rules:\n    - if: $CI_COMMIT_BRANCH\n": 0,
		"secrets-scan:\n  extends: [secret_detection]\n  rules:\n    - when: always\n":                       0,
		"secrets-scan:\n  extends: secret_detection\n":                                                       1,
		"secrets-scan:\n  extends: secret_detection\n  rules:\n    - when: never\n":                          1,
		"": 1,
	} {
		doc, err := parser.Parse([]byte(base+child), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL008.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("%q: got %d findings, want %d", child, got, want)
		}
	}
}

// A child that extends other jobs, or inherits a lone when: manual without
// rules, doesn't run the switched-off scan (#1000).
func TestGL008_ExtendingJobEdgeCases(t *testing.T) {
	for yml, want := range map[string]int{
		"include:\n  - template: Jobs/Secret-Detection.gitlab-ci.yml\nsecret_detection:\n  when: manual\nsecrets-scan:\n  extends: secret_detection\n":                                                                  1,
		"include:\n  - template: Jobs/Secret-Detection.gitlab-ci.yml\nsecret_detection:\n  rules:\n    - when: never\n.base:\n  stage: test\nother:\n  extends: [.base]\n  rules:\n    - when: always\n  script: [x]\n": 1,
	} {
		doc, err := parser.Parse([]byte(yml), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL008.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("%q: got %d findings, want %d", yml, got, want)
		}
	}
}
