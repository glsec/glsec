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
