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

func TestGL008_SAST_AllowFailure(t *testing.T) {
	f := findings008(t, `
sast:
  allow_failure: true
  variables:
    SAST_EXCLUDED_PATHS: "spec"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL008_SecretDetection_AllowFailure(t *testing.T) {
	f := findings008(t, `
secret_detection:
  allow_failure: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for secret_detection, got %d", len(f))
	}
}

func TestGL008_ContainerScanning_AllowFailure(t *testing.T) {
	f := findings008(t, `
container_scanning:
  allow_failure: true
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for container_scanning, got %d", len(f))
	}
}

func TestGL008_AllowFailureFalse_NoFinding(t *testing.T) {
	f := findings008(t, `
sast:
  allow_failure: false
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when allow_failure: false, got %d", len(f))
	}
}

func TestGL008_NoAllowFailure_NoFinding(t *testing.T) {
	f := findings008(t, `
sast:
  variables:
    SAST_EXCLUDED_PATHS: "spec"
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
sast:
  allow_failure:
    exit_codes: [1]
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for exit_codes form, got %d", len(f))
	}
}

func TestGL008_MultipleJobs(t *testing.T) {
	f := findings008(t, `
sast:
  allow_failure: true

dependency_scanning:
  allow_failure: true

build:
  allow_failure: true
  script: [make]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings (sast + dependency_scanning), got %d", len(f))
	}
}

func TestGL008_LineNumber(t *testing.T) {
	f := findings008(t, `
sast:
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
sast:
  when: manual
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for when: manual, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
	if f[0].Job != "sast" {
		t.Errorf("expected job attribution %q, got %q", "sast", f[0].Job)
	}
}

func TestGL008_WhenOnSuccess_NoFinding(t *testing.T) {
	f := findings008(t, `
sast:
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
sast:
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
		f := findings008(t, "sast:\n  rules:\n    - "+cond+"\n      when: never\n")
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
sast:
  allow_failure: true
  when: manual
`)
	if len(f) != 2 {
		t.Fatalf("expected both findings, got %d", len(f))
	}
}
