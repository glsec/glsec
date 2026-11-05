// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestJobVariablesPossible(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      []string
		unset     bool
	}{
		{"nowhere", "job: {script: [a]}", nil, true},
		{"global", "variables: {X: g}\njob: {script: [a]}", []string{"g"}, false},
		{"long form", "variables: {X: {value: g, description: d}}\njob: {script: [a]}", []string{"g"}, false},
		{"default", "default: {variables: {X: d}}\njob: {script: [a]}", []string{"d"}, false},
		{"top level over default", "variables: {X: g}\ndefault: {variables: {X: d}}\njob: {script: [a]}", []string{"g"}, false},
		{"job over global", "variables: {X: g}\njob: {variables: {X: j}}", []string{"j"}, false},
		{"empty job value", "variables: {X: g}\njob: {variables: {X: \"\"}}", []string{""}, false},
		{"template over global", "variables: {X: g}\n.t: {variables: {X: t}}\njob: {extends: .t}", []string{"t"}, false},
		{"job over template", ".t: {variables: {X: t}}\njob: {extends: .t, variables: {X: j}}", []string{"j"}, false},
		{"nearest base", ".a: {variables: {X: a}}\n.b: {extends: .a, variables: {X: b}}\njob: {extends: .b}", []string{"b"}, false},
		{"later parent wins", ".a: {variables: {X: a}}\n.b: {variables: {X: b}}\njob: {extends: [.a, .b]}", []string{"b"}, false},
		{"inherit false", "variables: {X: g}\njob: {inherit: {variables: false}}", nil, true},
		{"inherit list without it", "variables: {X: g}\njob: {inherit: {variables: [Y]}}", nil, true},
		{"inherit list with it", "variables: {X: g}\njob: {inherit: {variables: [X]}}", []string{"g"}, false},
		{"inherit doesn't touch the job's own", "job: {inherit: {variables: false}, variables: {X: j}}", []string{"j"}, false},
		{"rule next to the job's value", "job: {variables: {X: j}, rules: [{if: $A, variables: {X: r}}, {when: on_success}]}", []string{"r", "j"}, false},
		{"rule without another value", "job: {rules: [{if: $A, variables: {X: r}}, {when: on_success}]}", []string{"r"}, true},
		{"every rule sets it", "variables: {X: g}\njob: {rules: [{if: $A, variables: {X: a}}, {variables: {X: b}}]}", []string{"a", "b"}, false},
		{"a never rule doesn't run the job", "variables: {X: g}\njob: {rules: [{if: $A, when: never}, {variables: {X: r}}]}", []string{"r"}, false},
		{"only never rules", "variables: {X: g}\njob: {rules: [{if: $A, when: never}]}", []string{"g"}, false},
		{"template's rules", ".t: {rules: [{variables: {X: t}}]}\njob: {extends: .t}", []string{"t"}, false},
		{"job's rules replace the template's", ".t: {rules: [{variables: {X: t}}]}\njob: {extends: .t, rules: [{if: $A}]}", nil, true},
		{"workflow rule", "variables: {X: g}\nworkflow: {rules: [{if: $A, variables: {X: w}}, {when: always}]}\njob: {script: [a]}", []string{"w", "g"}, false},
		{"every workflow rule", "variables: {X: g}\nworkflow: {rules: [{variables: {X: w}}]}\njob: {script: [a]}", []string{"w"}, false},
		{"job over workflow", "workflow: {rules: [{variables: {X: w}}]}\njob: {variables: {X: j}}", []string{"j"}, false},
		{"rules as reference", "job: {rules: [!reference [.r, rules], {variables: {X: r}}]}", []string{"r"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := parseDoc(t, tc.src)
			in := NewInheritance(doc)
			v := variablesOf(in, parser.FindKey(parser.Unwrap(doc), "job"), pipelineVariablesOf(doc))
			got, unset := v.possible("X")
			if !slices.Equal(got, tc.want) || unset != tc.unset {
				t.Errorf("got %q unset=%v, want %q unset=%v", got, unset, tc.want, tc.unset)
			}
		})
	}
}

func TestGL090_EffectiveVariable(t *testing.T) {
	const scripts = "  script:\n    - npm ci\n    - npm publish\n"
	for _, tc := range []struct {
		name, src string
		want      int
	}{
		{"job turns the global off", "variables:\n  NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\npublish:\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"false\"\n" + scripts, 1},
		{"job turns the template's off", ".t:\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\npublish:\n  extends: .t\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"false\"\n" + scripts, 1},
		{"job sets it over a global false", "variables:\n  NPM_CONFIG_IGNORE_SCRIPTS: \"false\"\npublish:\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\n" + scripts, 0},
		{"template sets it", ".t:\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\npublish:\n  extends: .t\n" + scripts, 0},
		{"a rule turns it off", "variables:\n  NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\npublish:\n  rules:\n    - if: $A\n      variables:\n        NPM_CONFIG_IGNORE_SCRIPTS: \"false\"\n    - when: on_success\n" + scripts, 1},
		{"only one rule sets it", "publish:\n  rules:\n    - if: $A\n      variables:\n        NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\n    - when: on_success\n" + scripts, 1},
		{"every rule sets it", "publish:\n  rules:\n    - if: $A\n      variables:\n        NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\n" + scripts, 0},
		{"later parent wins", ".a:\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\n.b:\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"false\"\npublish:\n  extends: [.a, .b]\n" + scripts, 1},
		{"later parent protects", ".a:\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"false\"\n.b:\n  variables:\n    NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\npublish:\n  extends: [.a, .b]\n" + scripts, 0},
		{"yarn", "variables:\n  YARN_ENABLE_SCRIPTS: \"false\"\npublish:\n  variables:\n    YARN_ENABLE_SCRIPTS: \"true\"\n  script:\n    - yarn install\n    - yarn npm publish\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkRule(t, GL090, tc.src); len(got) != tc.want {
				t.Errorf("got %d findings, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

func TestGL090_EffectivePythonVariable(t *testing.T) {
	src := "variables:\n  PIP_ONLY_BINARY: \":all:\"\npublish:\n  variables:\n    PIP_ONLY_BINARY: \"\"\n  script:\n    - pip install -r requirements.txt\n    - twine upload dist/*\n"
	if got := checkRule(t, GL090, src); len(got) != 1 {
		t.Errorf("got %v", got)
	}
}

func TestGL089_EffectiveVariable(t *testing.T) {
	const run = "  script:\n    - renovate --autodiscover\n"
	for _, tc := range []struct {
		name, src string
		want      int
	}{
		{"job empties the global filter", "variables:\n  RENOVATE_AUTODISCOVER_FILTER: \"safe/*\"\nrenovate:\n  variables:\n    RENOVATE_AUTODISCOVER_FILTER: \"\"\n" + run, 1},
		{"global filter", "variables:\n  RENOVATE_AUTODISCOVER_FILTER: \"safe/*\"\nrenovate:\n" + run, 0},
		{"filter on one path only", "renovate:\n  rules:\n    - if: $A\n      variables:\n        RENOVATE_AUTODISCOVER_FILTER: \"safe/*\"\n    - when: on_success\n" + run, 1},
		{"switched on by a rule", "renovate:\n  rules:\n    - if: $A\n      variables:\n        RENOVATE_AUTODISCOVER: \"true\"\n    - when: on_success\n  script:\n    - renovate\n", 1},
		{"job switches the global off", "variables:\n  RENOVATE_AUTODISCOVER: \"true\"\nrenovate:\n  variables:\n    RENOVATE_AUTODISCOVER: \"false\"\n  script:\n    - renovate\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkRule(t, GL089, tc.src); len(got) != tc.want {
				t.Errorf("got %d findings, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}
