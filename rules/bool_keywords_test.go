// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
)

// A boolean keyword reads like GitLab reads it: yes and on are true, no and off
// are false, and a quoted value is a string (#1156). VALUE in src stands for
// the spelling, and each case gives the findings for a true and a false value.
func TestYAML11BooleanKeywords(t *testing.T) {
	for _, tc := range []struct {
		name          string
		rule          rule.Rule
		src           string
		onTrue, onOff int
	}{
		{"untracked GL014", GL014, "job:\n  script:\n    - env > env.txt\n  artifacts:\n    untracked: VALUE\n", 1, 0},
		{"untracked GL028", GL028, "job:\n  script: [a]\n  artifacts:\n    untracked: VALUE\n", 1, 0},
		{"public GL073", GL073, "job:\n  script: [a]\n  artifacts:\n    public: VALUE\n    paths: [a]\n", 1, 0},
		{"pipeline_variables GL010", GL010, "job:\n  trigger:\n    project: a/b\n    forward:\n      pipeline_variables: VALUE\n", 1, 0},
		{"pages GL013", GL013, "publish:\n  pages: VALUE\n  script: [a]\n", 1, 0},
	} {
		for _, v := range []struct {
			spelling string
			on       bool
		}{{"yes", true}, {"on", true}, {"Yes", true}, {"true", true}, {"no", false}, {"off", false}, {"OFF", false}, {"false", false}} {
			t.Run(tc.name+"/"+v.spelling, func(t *testing.T) {
				want := tc.onOff
				if v.on {
					want = tc.onTrue
				}
				got := checkRule(t, tc.rule, strings.ReplaceAll(tc.src, "VALUE", v.spelling))
				if len(got) != want {
					t.Errorf("got %d findings, want %d: %v", len(got), want, got)
				}
			})
		}
	}
}

func TestYAML11InheritDefault(t *testing.T) {
	src := "default:\n  before_script: [npm ci]\npublish:\n  inherit:\n    default: VALUE\n  script: [npm publish]\n"
	for spelling, want := range map[string]int{"no": 0, "off": 0, "false": 0, "yes": 1, "on": 1, "true": 1} {
		if got := checkRule(t, GL090, strings.ReplaceAll(src, "VALUE", spelling)); len(got) != want {
			t.Errorf("inherit:default: %s: got %d findings, want %d", spelling, len(got), want)
		}
	}
}

func TestYAML11FalseKeywords(t *testing.T) {
	for _, tc := range []struct {
		name string
		read func(string) bool
		key  string
	}{
		{"allow_failure", func(src string) bool { return allowFailureFalse(parser.Unwrap(parseDoc(t, src))) }, "allow_failure"},
		{"needs artifacts", func(src string) bool { return artifactsDisabled(parser.Unwrap(parseDoc(t, src))) }, "artifacts"},
	} {
		for value, want := range map[string]bool{"no": true, "off": true, "false": true, "yes": false, `"no"`: false} {
			if got := tc.read(tc.key + ": " + value + "\n"); got != want {
				t.Errorf("%s: %s = %v, want %v", tc.name, value, got, want)
			}
		}
	}
}

func TestYAML11Unprotect(t *testing.T) {
	src := "job:\n  rules:\n    - if: $CI_COMMIT_REF_PROTECTED == \"true\"\n  cache:\n    key: $CI_COMMIT_REF_SLUG\n    unprotect: VALUE\n    paths: [.cache/]\n  script: [make]\n"
	for spelling, want := range map[string]int{"yes": 1, "on": 1, "true": 1, "no": 0, "off": 0, `"yes"`: 0} {
		if got := findings046(t, strings.ReplaceAll(src, "VALUE", spelling)); len(got) != want {
			t.Errorf("unprotect: %s: got %d findings, want %d", spelling, len(got), want)
		}
	}
}
