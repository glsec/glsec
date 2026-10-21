// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings085(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL085.Check(doc.Root, "test.yml")
}

func TestGL085_Lines(t *testing.T) {
	cases := []struct {
		line string
		want finding.Severity // "" = no finding
	}{
		// approvals disabled, job not on merge request pipelines
		{`claude -p "review the diff" --dangerously-skip-permissions`, finding.Warn},
		{`claude -p "fix lint" --permission-mode bypassPermissions`, finding.Warn},
		{`claude -p "fix lint" --allowedTools "Bash,Edit"`, finding.Warn},
		{`claude -p "fix lint" --allowed-tools 'Bash(*)' Read`, finding.Warn},
		{`codex exec --dangerously-bypass-approvals-and-sandbox "fix"`, finding.Warn},
		{`codex exec --yolo "fix"`, finding.Warn},
		{`codex exec -s danger-full-access "fix"`, finding.Warn},
		{`gemini --yolo -p "summarise"`, finding.Warn},
		{`gemini -y -p "summarise"`, finding.Warn},
		{`gemini --approval-mode=yolo -p "summarise"`, finding.Warn},
		{`copilot -p "triage" --allow-all-tools`, finding.Warn},
		{`npx -y @anthropic-ai/claude-code -p "x" --dangerously-skip-permissions`, finding.Warn},
		{`ANTHROPIC_MODEL=opus ./node_modules/.bin/claude -p "x" --dangerously-skip-permissions`, finding.Warn},
		// untrusted text in the prompt, quoted or not
		{`claude -p "Review MR: $CI_MERGE_REQUEST_TITLE"`, finding.Warn},
		{`gemini -p "${AI_FLOW_INPUT}"`, finding.Warn},
		{`copilot --prompt "$CI_COMMIT_MESSAGE"`, finding.Warn},
		// both
		{`claude -p "Review: $CI_MERGE_REQUEST_DESCRIPTION" --dangerously-skip-permissions`, finding.Error},
		// restricted or unrelated
		{`claude -p "review" --allowedTools "Read,Grep,Bash(git diff:*)"`, ""},
		{`claude -p "review" --permission-mode acceptEdits`, ""},
		{`claude -p "review" --allowedTools "Grep,Bash(git --no-pager diff:*),Bash(git log:*)"`, ""},
		{`claude -p "review" --allowedTools "Read Bash(git --no-pager log:*) Bash"`, finding.Warn},
		{`codex exec -s workspace-write "fix"`, ""},
		{`gemini --approval-mode auto_edit -p "x"`, ""},
		{`npm install -g @anthropic-ai/claude-code`, ""},
		{`echo "claude --dangerously-skip-permissions is risky"`, ""},
		{`copilot svc deploy --env "$CI_COMMIT_REF_NAME"`, ""},
		{`claude -p "summarise $CI_PROJECT_NAME"`, ""},
		{`claude -p "x" | apt-get install -y jq`, ""},
		{`gemini -p "x" && docker run --yolo`, ""},
	}
	for _, tc := range cases {
		f := findings085(t, "job:\n  script:\n    - '"+strings.ReplaceAll(tc.line, "'", "''")+"'\n")
		switch {
		case tc.want == "" && len(f) != 0:
			t.Errorf("%s: expected no finding, got %q", tc.line, f[0].Message)
		case tc.want != "" && len(f) != 1:
			t.Errorf("%s: expected 1 finding, got %d", tc.line, len(f))
		case tc.want != "" && f[0].Severity != tc.want:
			t.Errorf("%s: severity %s, want %s", tc.line, f[0].Severity, tc.want)
		}
	}
}

func TestGL085_MergeRequestJobIsError(t *testing.T) {
	for name, src := range map[string]string{
		"job rules": `
review:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - claude -p "review" --dangerously-skip-permissions
`,
		"workflow admits merge requests, job unguarded": `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
review:
  script:
    - claude -p "review" --dangerously-skip-permissions
`,
	} {
		f := findings085(t, src)
		if len(f) != 1 || f[0].Severity != finding.Error {
			t.Errorf("%s: expected one error, got %+v", name, f)
		}
	}
}

func TestGL085_GuardedJobStaysWarn(t *testing.T) {
	f := findings085(t, `
workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
nightly-fix:
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - codex exec --yolo "update dependencies"
`)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Errorf("expected one warning, got %+v", f)
	}
}

func TestGL085_LineContinuation(t *testing.T) {
	f := findings085(t, `
review:
  script:
    - |
      claude -p "Review $CI_MERGE_REQUEST_TITLE" \
        --dangerously-skip-permissions
`)
	if len(f) != 1 || f[0].Severity != finding.Error {
		t.Errorf("expected one error across a line continuation, got %+v", f)
	}
}
