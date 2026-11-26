// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestNewRefScope(t *testing.T) {
	for name, tc := range map[string]struct {
		workflow                   string
		protectedOnly, mrPipelines bool
	}{
		"no workflow":       {"", false, true},
		"default branch":    {"workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n", true, false},
		"branches only":     {"workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n", false, false},
		"branch and MR":     {"workflow:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n    - if: $CI_COMMIT_BRANCH\n", false, true},
		"unconditional":     {"workflow:\n  rules:\n    - when: always\n", false, true},
		"protected and MR":  {"workflow:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n    - if: $CI_COMMIT_TAG\n", false, true},
		"tags, never first": {"workflow:\n  rules:\n    - if: $CI_COMMIT_MESSAGE =~ /wip/\n      when: never\n    - if: $CI_COMMIT_TAG\n", true, false},
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.workflow+"job:\n  script: [true]\n"), "test.yml")
			if err != nil {
				t.Fatal(err)
			}
			s := newRefScope(parser.Unwrap(doc.Root))
			if s.protectedOnly != tc.protectedOnly || s.mrPipelines != tc.mrPipelines {
				t.Errorf("got %+v, want protectedOnly=%v mrPipelines=%v", s, tc.protectedOnly, tc.mrPipelines)
			}
		})
	}
}

func TestIncludeRulesProtectedOnly(t *testing.T) {
	for rules, want := range map[string]bool{
		"- if: $CI_COMMIT_TAG\n":                                              true,
		"- if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n":                     true,
		"- if: $CI_COMMIT_TAG =~ /^v/\n- if: $CI_COMMIT_BRANCH == \"main\"\n": true,
		"- if: $CI_COMMIT_TAG\n- when: always\n":                              false,
		"- exists: [Dockerfile]\n":                                            false,
		"- if: $CI_COMMIT_BRANCH\n":                                           false,
		"- if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n":              false,
		"- if: $SKIP == \"1\"\n  when: never\n- if: $CI_COMMIT_TAG\n":         true,
	} {
		doc := parseDoc(t, "rules:\n"+indent(rules))
		if got := IncludeRulesProtectedOnly(parser.FindKey(parser.Unwrap(doc), "rules")); got != want {
			t.Errorf("rules\n%s: got %v, want %v", rules, got, want)
		}
	}
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\n  ") + "\n"
}

// include: rules read as a job's own rules: (#1531).
func TestIncludeRulesRestricted(t *testing.T) {
	for _, tc := range []struct {
		rules       string
		child, want bool
	}{
		{"- if: $CI_PIPELINE_SOURCE == \"schedule\" && $KIND == \"daily\"\n", false, true},
		{"- if: $CI_PIPELINE_SOURCE == \"web\"\n", false, true},
		{"- if: $DEPLOY_DOCS == \"true\"\n", false, true},
		{"- if: $CI_COMMIT_TAG\n", false, true},
		{"- if: $CI_PIPELINE_SOURCE == \"schedule\"\n- when: always\n", false, false},
		{"- exists: [Dockerfile]\n", false, false},
		{"- changes: [docs/**]\n", false, false},
		{"- if: $CI_COMMIT_BRANCH\n", false, false},
		{"- if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n", false, false},
		{"- if: $CI_PIPELINE_SOURCE == \"parent_pipeline\"\n", false, true},
		{"- if: $CI_PIPELINE_SOURCE == \"parent_pipeline\"\n", true, false},
		{"- if: $SKIP\n  when: never\n", false, false},
		{"- if: $SKIP\n  when: never\n- if: $CI_PIPELINE_SOURCE == \"schedule\"\n", false, true},
		{"- !reference [.rules, schedule]\n", false, false},
		{"- if: $CI_PIPELINE_SOURCE != \"schedule\"\n", false, false},
		{"- if: $CI_COMMIT_MESSAGE =~ /(infra|all)/\n", false, false},
		{"- if: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == \"development\"\n", false, false},
		{"- if: $CI_COMMIT_BRANCH == \"development\"\n- if: $CI_MERGE_REQUEST_TARGET_BRANCH_NAME == \"development\"\n", false, false},
		{"- if: $CI_PIPELINE_SOURCE == \"push\"\n", false, false},
		{"- if: $CI_PIPELINE_SOURCE == \"push\" && $CI_COMMIT_BRANCH == \"main\"\n- if: $FORCE_BUILD == \"true\"\n", false, true},
		{"- if: $CI_PIPELINE_SOURCE == \"schedule\" || $CI_COMMIT_BRANCH\n", false, false},
		{"- if: ($CI_PIPELINE_SOURCE == \"web\")\n", false, true},
		{"- if: $DEPLOY != \"false\"\n", false, false},
		{"- if: $KIND =~ /daily/\n", false, true},
	} {
		doc := parseDoc(t, "rules:\n"+indent(tc.rules))
		if got := IncludeRulesRestricted(parser.FindKey(parser.Unwrap(doc), "rules"), tc.child); got != tc.want {
			t.Errorf("rules (child %v)\n%s: got %v, want %v", tc.child, tc.rules, got, tc.want)
		}
	}
	if IncludeRulesRestricted(nil, false) {
		t.Error("no rules: restricts nothing")
	}
}

func TestOpenOnAnyBranch(t *testing.T) {
	for _, tc := range []struct {
		expr string
		mr   bool
		open bool
	}{
		{`$CI_PIPELINE_SOURCE != "schedule"`, false, true},
		{`$CI_PIPELINE_SOURCE != "push"`, false, false},
		{`$CI_PIPELINE_SOURCE != "push"`, true, true},
		{`$CI_PIPELINE_SOURCE !~ /push|merge_request_event/`, true, false},
		{`$CI_PIPELINE_SOURCE !~ /^PUSH$/i`, false, false},
		{`$CI_PIPELINE_SOURCE !~ /(/`, false, false},
		{`$CI_PIPELINE_SOURCE == "push"`, false, false},
		{`$CI_COMMIT_MESSAGE =~ /\[deploy\]/`, false, true},
		{`$CI_COMMIT_AUTHOR == "Jane <j@example.com>"`, false, true},
		{`$CI_COMMIT_DESCRIPTION`, false, true},
		{`$CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "main"`, false, false},
		{`$CI_MERGE_REQUEST_TARGET_BRANCH_NAME == "main"`, true, true},
		{`$CI_MERGE_REQUEST_IID != null`, false, false},
		{`$CI_MERGE_REQUEST_IID == null`, false, true},
		{`$CI_MERGE_REQUEST_IID == ""`, false, true},
		{`$CI_MERGE_REQUEST_SOURCE_BRANCH_PROTECTED == "true"`, true, false},
		{`$CI_MERGE_REQUEST_SOURCE_BRANCH_PROTECTED != "true"`, true, false},
		{`$CI_MERGE_REQUEST_APPROVED == "true"`, true, false},
		{`$CI_MERGE_REQUEST_EVENT_TYPE == "merge_train"`, true, false},
		{`($CI_COMMIT_MESSAGE =~ /x/) && $CI_COMMIT_BRANCH`, false, true},
		{`$CI_COMMIT_MESSAGE =~ /x/ && $CI_COMMIT_REF_PROTECTED == "true"`, false, false},
		{`$CI_COMMIT_MESSAGE =~ /x/ && ($A || $B)`, false, false},
		{`$DEPLOY == "true" || $CI_PIPELINE_SOURCE != "schedule"`, false, true},
		{`$CI_COMMIT_BRANCH`, false, true},
		{`$CI_COMMIT_MESSAGE =~ /x/ || ($CI_COMMIT_BRANCH`, false, false},
	} {
		if got := openOnAnyBranch(tc.expr, tc.mr) != ""; got != tc.open {
			t.Errorf("openOnAnyBranch(%q, mr=%v) = %v, want %v", tc.expr, tc.mr, got, tc.open)
		}
	}
}

func TestIfAdmitsMR(t *testing.T) {
	for expr, want := range map[string]bool{
		`$CI_PIPELINE_SOURCE == "merge_request_event"`:                                                 true,
		`"merge_request_event" == $CI_PIPELINE_SOURCE`:                                                 true,
		`$CI_PIPELINE_SOURCE =~ /^(push|merge_request_event)$/`:                                        true,
		`$CI_PIPELINE_SOURCE =~ /merge_request/`:                                                       true,
		`$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_MERGE_REQUEST_IID`:                        true,
		`$CI_PIPELINE_SOURCE == "merge_request_event" || $CI_COMMIT_BRANCH == "main"`:                  true,
		`$CI_PIPELINE_SOURCE == "merge_request_event" || $CI_PIPELINE_SOURCE != "push"`:                true,
		`$CI_COMMIT_TAG && ($CI_PIPELINE_SOURCE == "merge_request_event" || $X)`:                       true,
		`$CI_PIPELINE_SOURCE != "merge_request_event"`:                                                 false,
		`$CI_PIPELINE_SOURCE !~ /^(push|merge_request_event)$/`:                                        false,
		`$CI_PIPELINE_SOURCE !~ /merge_request_event/`:                                                 false,
		`$CI_PIPELINE_SOURCE !~ /^schedule$/ && $CI_PIPELINE_SOURCE == "merge_request_event"`:          true,
		`$CI_PIPELINE_SOURCE == "merge_request_event" && $CI_PIPELINE_SOURCE != "merge_request_event"`: false,
		`$CI_PIPELINE_SOURCE == "push" && $CI_PIPELINE_SOURCE == "merge_request_event"`:                false,
		`$CI_PIPELINE_SOURCE == "push"`:                                                                false,
		`$CI_COMMIT_BRANCH`:                                                                            false,
		`$CI_PIPELINE_SOURCE == "merge_request_event" || ($CI_COMMIT_BRANCH`:                           true,
		`$CI_PIPELINE_SOURCE != "merge_request_event" || ($CI_COMMIT_BRANCH`:                           false,
	} {
		if got := ifAdmitsMR(expr); got != want {
			t.Errorf("ifAdmitsMR(%q) = %v, want %v", expr, got, want)
		}
	}
}
