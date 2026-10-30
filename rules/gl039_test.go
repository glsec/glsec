// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func TestGL039(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "npm audit silenced with || true",
			yaml: `security:
  script:
    - npm audit --audit-level=high || true`,
			wantHits: 1,
		},
		{
			name: "composer audit silenced",
			yaml: `security:
  script:
    - composer audit || true`,
			wantHits: 1,
		},
		{
			name: "trivy silenced",
			yaml: `scan:
  script:
    - trivy image myapp:latest || true`,
			wantHits: 1,
		},
		{
			name: "snyk silenced with || exit 0",
			yaml: `security:
  script:
    - snyk test || exit 0`,
			wantHits: 1,
		},
		{
			name: "npm audit without silencing — safe",
			yaml: `security:
  script:
    - npm audit --audit-level=high`,
			wantHits: 0,
		},
		{
			name: "unrelated command silenced — safe",
			yaml: `build:
  script:
    - make lint || true`,
			wantHits: 0,
		},
		{
			name: "multiple tools silenced",
			yaml: `security:
  script:
    - npm audit || true
    - trivy image myapp || true
    - snyk test`,
			wantHits: 2,
		},
		{
			name: "inspector check silenced",
			yaml: `security:
  script:
    - inspector check soup.json || true`,
			wantHits: 1,
		},
		{
			name: "osv-scanner silenced",
			yaml: `security:
  script:
    - osv-scanner --lockfile package-lock.json || true`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL039.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}

func findings039(t *testing.T, line string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte("security:\n  script:\n    - "+strconv.Quote(line)+"\n"), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL039.Check(doc.Root, "test.yml")
}

func TestGL039_MoreScanners(t *testing.T) {
	cases := map[string]string{
		"pnpm audit":          "pnpm audit --prod || true",
		"yarn audit":          "yarn audit --level high || true",
		"gitleaks":            "gitleaks detect --source . || true",
		"trufflehog":          "trufflehog git file://. --fail || true",
		"ggshield":            "ggshield secret scan ci || true",
		"detect-secrets":      "detect-secrets scan --baseline .secrets.baseline || true",
		"detect-secrets-hook": "detect-secrets-hook --baseline .secrets.baseline src/*.py || true",
		"semgrep":             "semgrep ci || true",
		"gosec":               "gosec ./... || true",
		"bandit":              "bandit -r src || true",
		"brakeman":            "bundle exec brakeman -q || true",
		"checkov":             "checkov -d . || true",
		"tfsec":               "tfsec . || true",
		"kics":                "kics scan -p . || true",
		"terrascan":           "terrascan scan || true",
		"kubescape":           "kubescape scan framework nsa || true",
		"govulncheck":         "go run golang.org/x/vuln/cmd/govulncheck@latest ./... || true",
		"pip-audit":           "pip-audit -r requirements.txt || true",
		"pip_audit module":    "python -m pip_audit || true",
		"dependency-check":    "/usr/share/dependency-check/bin/dependency-check.sh --scan . || true",
		"cargo audit":         "cargo audit || true",
		"cargo deny":          "cargo deny check || true",
		"bundle-audit":        "bundle exec bundle-audit check --update || true",
		"bundle audit":        "bundle audit || true",
		"after assignment":    "SEMGREP_APP_TOKEN=$TOKEN semgrep ci || true",
		"after &&":            "cd infra && checkov -d . || true",
		"colon silencer":      "gitleaks detect || :",
		"exit 0 silencer":     "gosec ./... || exit 0",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if f := findings039(t, line); len(f) != 1 {
				t.Errorf("expected 1 finding for %q, got %d", line, len(f))
			}
		})
	}
}

func TestGL039_SilencerInMessage(t *testing.T) {
	f := findings039(t, "gitleaks detect || :")
	if len(f) != 1 || !strings.Contains(f[0].Message, `"|| :"`) {
		t.Errorf("the message must name the silencer used, got %v", f)
	}
}

func TestGL039_InstallStepsNotScanners(t *testing.T) {
	for _, line := range []string{
		"pip install pip-audit || true",
		"pip install semgrep checkov bandit || true",
		"go install github.com/securego/gosec/v2/cmd/gosec@latest || true",
		"cargo install cargo-audit cargo-deny || true",
		"gem install brakeman bundler-audit || true",
		"apk add --no-cache gitleaks || true",
		"echo semgrep finished || true",
		"rm -rf .gosec-cache || true",
		"gitleaks detect --source .",
		"semgrep ci || true_flag_value",
	} {
		if f := findings039(t, line); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %v", line, f)
		}
	}
}

// A silenced report run followed by a run that gates the job is fine, and
// `|| echo` silences like `|| true` unless a failing exit follows (#988).
func TestGL039_GatingRerunAndEcho(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{"- trivy fs . --format json --output report.json || true\n    - trivy fs . --severity HIGH,CRITICAL --exit-code 1", 0},
		{"- trivy fs . --format json --output report.json || true\n    - echo done", 1},
		{`- uv run bandit -r src || echo "issues found"`, 1},
		{`- bandit -r src || echo "issues found" && exit 1`, 0},
		{`- bandit -r src || echo "issues found"; exit 2`, 0},
	} {
		doc, err := parser.Parse([]byte("scan:\n  script:\n    "+tc.script+"\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL039.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%q: got %d findings, want %d", tc.script, got, tc.want)
		}
	}
}
