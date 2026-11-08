// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings091(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL091.Check(doc.Root, "test.yml")
}

func TestGL091_JobRulesIf(t *testing.T) {
	for _, tc := range []struct {
		cond string
		want string // spoofed variable, "" for no finding
	}{
		{`$CI_COMMIT_AUTHOR =~ /renovate/`, "CI_COMMIT_AUTHOR"},
		{`$CI_COMMIT_AUTHOR =~ /^Renovate Bot <bot@example\.invalid>$/`, "CI_COMMIT_AUTHOR"},
		{`$CI_COMMIT_AUTHOR == "release-bot <release-bot@example.invalid>"`, "CI_COMMIT_AUTHOR"},
		{`${CI_COMMIT_AUTHOR} == "x"`, "CI_COMMIT_AUTHOR"},
		{`$GITLAB_USER_NAME == "renovate"`, "GITLAB_USER_NAME"},
		{`"renovate" == $GITLAB_USER_NAME`, "GITLAB_USER_NAME"},
		{`$CI_COMMIT_USER_LOGIN == "release-bot"`, "CI_COMMIT_USER_LOGIN"},
		{`$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $CI_COMMIT_AUTHOR =~ /bot/`, "CI_COMMIT_AUTHOR"},
		{`$CI_PIPELINE_SOURCE == "push" || $GITLAB_USER_NAME =~ /admin/i`, "GITLAB_USER_NAME"},
		{`$CI_COMMIT_AUTHOR != "release-bot <release-bot@example.invalid>"`, ""},
		{`$CI_COMMIT_AUTHOR !~ /renovate/`, ""},
		{`$GITLAB_USER_NAME != "renovate"`, ""},
		{`$GITLAB_USER_LOGIN == "renovate-bot"`, ""},
		{`$GITLAB_USER_ID == "123"`, ""},
		{`$GITLAB_USER_EMAIL == "bot@example.invalid"`, ""},
		{`$CI_COMMIT_AUTHOR == null`, ""},
		{`$CI_COMMIT_AUTHOR`, ""},
		{`$CI_COMMIT_AUTHORS == "x"`, ""},
	} {
		y := "job:\n  rules:\n    - if: '" + strings.ReplaceAll(tc.cond, "'", "''") + "'\n  script: [echo]\n"
		f := findings091(t, y)
		switch {
		case tc.want == "" && len(f) != 0:
			t.Errorf("%s: want no finding, got %+v", tc.cond, f)
		case tc.want != "" && (len(f) != 1 || !strings.Contains(f[0].Message, "$"+tc.want+",") || f[0].Job != "job" || f[0].Line != 3):
			t.Errorf("%s: want one finding for %s on line 3, got %+v", tc.cond, tc.want, f)
		}
	}
}

func TestGL091_WorkflowIncludeAndWhenNever(t *testing.T) {
	f := findings091(t, `
workflow:
  rules:
    - if: $GITLAB_USER_NAME == "deployer"
include:
  - local: release.yml
    rules:
      - if: $CI_COMMIT_AUTHOR =~ /release-bot/
skip-bot:
  rules:
    - if: $CI_COMMIT_AUTHOR =~ /renovate/
      when: never
    - when: on_success
  script: [echo]
`)
	if len(f) != 2 || f[0].Line != 4 || f[1].Line != 8 || f[0].Job != "" || f[1].Job != "" {
		t.Fatalf("want workflow (line 4) and include (line 8) findings, got %+v", f)
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("severity: got %s", f[0].Severity)
	}
}

// In a push pipeline GITLAB_USER_NAME is the pusher, who wrote the YAML: such
// a gate grants nothing. Commit-derived identities stay reported (#1287).
func TestGL091_PushOnlyGate(t *testing.T) {
	for cond, want := range map[string]int{
		`$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == "main" && $GITLAB_USER_NAME == "Jane Doe"`:  0,
		`$GITLAB_USER_NAME == "Jane Doe" && "push" == $CI_PIPELINE_SOURCE`:                                 0,
		`$CI_PIPELINE_SOURCE == 'push' && $GITLAB_USER_NAME =~ /bot/`:                                      0,
		`$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_AUTHOR =~ /Renovate/`:                                 1,
		`$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_USER_LOGIN == "jane"`:                                 1,
		`$CI_PIPELINE_SOURCE == "merge_request_event" && $GITLAB_USER_NAME == "chore-mr"`:                  1,
		`$CI_PIPELINE_SOURCE == "push" || $GITLAB_USER_NAME == "Jane Doe"`:                                 1,
		`($CI_PIPELINE_SOURCE == "push" || $CI_PIPELINE_SOURCE == "web") && $GITLAB_USER_NAME == "Jane"`:   1,
		`$CI_PIPELINE_SOURCE == "schedule" || ($CI_PIPELINE_SOURCE == "push" && $GITLAB_USER_NAME == "J")`: 1,
	} {
		t.Run(cond, func(t *testing.T) {
			f := findings091(t, "job:\n  script: [make]\n  rules:\n    - if: '"+strings.ReplaceAll(cond, "'", "''")+"'\n")
			if len(f) != want {
				t.Fatalf("got %v, want %d findings", f, want)
			}
		})
	}
}
