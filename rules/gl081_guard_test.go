package rules

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIfRestrictsToProtected(t *testing.T) {
	tests := []struct {
		expr string
		want bool
	}{
		// Restricting forms.
		{`$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`, true},
		{`$CI_DEFAULT_BRANCH == $CI_COMMIT_BRANCH`, true},
		{`$CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH`, true},
		{`$CI_COMMIT_TAG`, true},
		{`$CI_COMMIT_TAG =~ /^v\d+/`, true},
		{`$CI_COMMIT_TAG != null`, true},
		{`$CI_COMMIT_REF_PROTECTED == "true"`, true},
		{`$CI_COMMIT_REF_PROTECTED == 'true'`, true},
		{`$CI_COMMIT_BRANCH == "main"`, true},
		{`$CI_COMMIT_REF_NAME == 'release'`, true},
		{`$CI_COMMIT_BRANCH == "main" || $CI_COMMIT_TAG`, true},
		{`$CI_PIPELINE_SOURCE == "push" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`, true},
		{`($CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH)`, true},

		// Not restricting: negations.
		{`$CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH`, false},
		{`$CI_COMMIT_TAG == null`, false},
		{`$CI_COMMIT_REF_PROTECTED != "true"`, false},
		{`$CI_COMMIT_REF_PROTECTED == "false"`, false},
		{`$CI_COMMIT_BRANCH != "main"`, false},
		// Not restricting: one alternative of an || admits other refs.
		{`$CI_COMMIT_REF_PROTECTED == "true" || $CI_COMMIT_BRANCH =~ /^feature/`, false},
		{`$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH || $CI_PIPELINE_SOURCE == "schedule"`, false},
		// Not restricting: no ref condition at all.
		{`$CI_PIPELINE_SOURCE == "push"`, false},
		{`$CI_COMMIT_BRANCH`, false},
		{`$CI_COMMIT_REF_PROTECTED`, false}, // "false" is a non-empty string, so this is always true
		{`$CI_COMMIT_BRANCH =~ /^release/`, false},
	}
	for _, tt := range tests {
		if got := ifRestrictsToProtected(tt.expr); got != tt.want {
			t.Errorf("ifRestrictsToProtected(%q) = %v, want %v", tt.expr, got, tt.want)
		}
	}
}

// A workflow that only looks like it restricts the pipeline must not suppress
// GL081 for the whole file.
func TestGL081_WorkflowLooksRestrictedButIsNot(t *testing.T) {
	for _, cond := range []string{
		`$CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH`,
		`$CI_COMMIT_REF_PROTECTED != "true"`,
		`$CI_COMMIT_REF_PROTECTED == "true" || $CI_COMMIT_BRANCH =~ /^feature/`,
		`$CI_COMMIT_TAG == null`,
	} {
		src := "workflow:\n  rules:\n    - if: '" + strings.ReplaceAll(cond, "'", "''") + "'\n" + `
oidc-job:
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - ./run.sh
`
		if f := findings081(t, src); len(f) != 1 {
			t.Errorf("workflow if %q suppressed GL081 (got %d findings, want 1)", cond, len(f))
		}
	}
}

func TestGL081_WorkflowEdgeCases(t *testing.T) {
	job := `
oidc-job:
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - ./run.sh
`
	tests := []struct {
		name     string
		workflow string
		want     int
	}{
		{"workflow without rules", "workflow:\n  name: x\n", 1},
		{"unconditional rule", "workflow:\n  rules:\n    - when: always\n", 1},
		{"only when: never rules", "workflow:\n  rules:\n    - if: $CI_COMMIT_TAG\n      when: never\n", 1},
		{"never for MRs, then protected", "workflow:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n      when: never\n    - if: $CI_COMMIT_REF_PROTECTED == \"true\"\n", 0},
		{"rules is not a list", "workflow:\n  rules: {}\n", 1},
	}
	for _, tt := range tests {
		if f := findings081(t, tt.workflow+job); len(f) != tt.want {
			t.Errorf("%s: got %d findings, want %d", tt.name, len(f), tt.want)
		}
	}
}

func TestOnlyAdmitsMR(t *testing.T) {
	tests := []struct {
		src  string
		want bool
	}{
		{`merge_requests`, true},
		{`[main, merge_requests]`, true},
		{`{refs: [merge_requests]}`, true},
		{`{refs: merge_requests}`, true},
		{`{refs: [main]}`, false},
		{`{variables: [$X]}`, false},
		{`[main, tags]`, false},
		{`main`, false},
	}
	for _, tt := range tests {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(tt.src), &n); err != nil {
			t.Fatal(err)
		}
		if got := onlyAdmitsMR(n.Content[0]); got != tt.want {
			t.Errorf("onlyAdmitsMR(%s) = %v, want %v", tt.src, got, tt.want)
		}
	}
	if onlyAdmitsMR(nil) {
		t.Error("onlyAdmitsMR(nil) = true")
	}
}

func TestGL081_OnlyRefsMergeRequests(t *testing.T) {
	f := findings081(t, `
oidc-job:
  only:
    refs:
      - merge_requests
  id_tokens:
    ID_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - ./run.sh
`)
	if len(f) != 1 {
		t.Fatalf("only: refs: [merge_requests] should be flagged, got %d findings", len(f))
	}
}
