// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
)

func checkRule(t *testing.T, r rule.Rule, src string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return Check(r, doc, "test.yml")
}

// ruleVariableCases are one variable per rule family that the rule reports in
// variables:. Each line is indented for a variables: block inside a rules:
// entry; the first line of the variable is where the finding points.
var ruleVariableCases = []struct {
	r    rule.Rule
	vars string
}{
	{GL006, `API_TOKEN: "gl` + `pat-` + strings.Repeat("x", 20) + `"`},
	{GL016, `PIP_INDEX_URL: "http://pypi.internal.example/simple"`},
	{GL027, "DEPLOY_PASSWORD:\n            value: \"staging-pw-2024\"\n            description: \"staging deploy user\""},
	{GL031, `DOCKER_TLS_CERTDIR: ""`},
	{GL033, `CI_DEBUG_TRACE: "true"`},
	{GL036, `DATABASE_URL: "postgres://myapp:s3cr3t@postgres:5432/mydb"`},
	{GL042, `GIT_SSL_NO_VERIFY: "true"`},
	{GL054, `DOCKER_HOST: tcp://docker:2375`},
	{GL055, `DOCKER_HOST: unix:///var/run/docker.sock`},
	{GL066, `DOCKER_AUTH_CONFIG: '{"auths":{"registry.example.com":{"auth":"dXNlcjpwYXNz"}}}'`},
	{GL067, `SECURE_ANALYZERS_PREFIX: registry.attacker.example/analyzers`},
	{GL069, `GONOSUMDB: "*"`},
	{GL082, `SAST_DISABLED: "true"`},
}

// A value moved from variables: into a rules: entry is reported all the same,
// at its line in the rule (#672).
func TestRuleVariables_WorkflowAndJobRules(t *testing.T) {
	for _, tc := range ruleVariableCases {
		t.Run(tc.r.ID(), func(t *testing.T) {
			workflow := fmt.Sprintf(`workflow:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      variables:
          %s
build:
  script: [make]
`, tc.vars)
			job := fmt.Sprintf(`build:
  script: [make]
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      variables:
          %s
`, tc.vars)
			for _, c := range []struct {
				name, src, job string
				line           int
			}{
				{"workflow:rules", workflow, "", 5},
				{"job rules", job, "build", 6},
			} {
				f := checkRule(t, tc.r, c.src)
				if len(f) != 1 {
					t.Errorf("%s: expected 1 finding, got %d: %v", c.name, len(f), f)
					continue
				}
				if f[0].Line != c.line || f[0].Job != c.job {
					t.Errorf("%s: finding at line %d, job %q; want line %d, job %q", c.name, f[0].Line, f[0].Job, c.line, c.job)
				}
			}
		})
	}
}

// The example from #672 gives the same rules as with the values in variables:.
func TestRuleVariables_IssueExample(t *testing.T) {
	values := `CI_DEBUG_TRACE: "true"
        GONOSUMDB: "*"
        SAST_DISABLED: "true"
        PIP_INDEX_URL: "http://pypi.internal.example/simple"
        API_TOKEN: "gl` + `pat-` + strings.Repeat("x", 20) + `"`
	inRules := "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n      variables:\n        " + values + "\nbuild:\n  script: [make]\n"
	inVariables := "variables:\n        " + values + "\nbuild:\n  script: [make]\n"
	ids := func(src string) map[string]bool {
		got := map[string]bool{}
		for _, r := range All() {
			if len(checkRule(t, r, src)) > 0 {
				got[r.ID()] = true
			}
		}
		delete(got, "GL053") // about workflow:rules itself
		return got
	}
	want, got := ids(inVariables), ids(inRules)
	for _, id := range []string{"GL006", "GL016", "GL033", "GL069", "GL082"} {
		if !want[id] {
			t.Errorf("%s doesn't fire on the variables: version; the test data is wrong", id)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("rules:variables gives %v, variables: gives %v", got, want)
	}
}

func TestRuleVariables_GL082ScheduleOnly(t *testing.T) {
	for cond, want := range map[string]int{
		`$CI_PIPELINE_SOURCE == "schedule"`:                                  0,
		`$CI_PIPELINE_SOURCE == 'schedule' && $CI_COMMIT_BRANCH == "main"`:   0,
		`$CI_PIPELINE_SOURCE == "schedule" || $CI_PIPELINE_SOURCE == "push"`: 1,
		`$CI_PIPELINE_SOURCE == "push"`:                                      1,
	} {
		f := checkRule(t, GL082, fmt.Sprintf(`workflow:
  rules:
    - if: %q
      variables:
        SAST_DISABLED: "true"
build:
  script: [make]
`, cond))
		if len(f) != want {
			t.Errorf("%s: expected %d findings, got %d", cond, want, len(f))
		}
	}
}

func TestRuleVariables_GL001ImageTag(t *testing.T) {
	f := checkRule(t, GL001, `
build:
  image: $NODE_IMAGE
  variables:
    NODE_IMAGE: node:22.11
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      variables:
        NODE_IMAGE: node:latest
  script: [make]
`)
	if len(f) != 1 || !strings.Contains(f[0].Message, "latest") {
		t.Errorf("expected the rule's latest tag to be reported, got %v", f)
	}

	f = checkRule(t, GL001, `
workflow:
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      variables:
        BASE_IMAGE: alpine:latest
build:
  image: $BASE_IMAGE
  script: [make]
`)
	if len(f) != 1 {
		t.Errorf("expected a finding for the workflow:rules image, got %v", f)
	}
}

func TestRuleVariables_PipelineLevelOnly(t *testing.T) {
	src := func(where string) string {
		if where == "workflow" {
			return `workflow:
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      variables:
        PROD_API_TOKEN: $PROD_API_TOKEN
deploy:
  trigger:
    project: group/downstream
`
		}
		return `deploy:
  trigger:
    project: group/downstream
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      variables:
        PROD_API_TOKEN: $PROD_API_TOKEN
`
	}
	for _, r := range []rule.Rule{GL018, GL037} {
		if n := len(checkRule(t, r, src("workflow"))); n != 1 {
			t.Errorf("%s: expected 1 finding for workflow:rules variables, got %d", r.ID(), n)
		}
		if n := len(checkRule(t, r, src("job"))); n != 0 {
			t.Errorf("%s: job rules variables are not pipeline-level, got %d findings", r.ID(), n)
		}
	}
}

func TestRuleVariables_GL054ServiceWins(t *testing.T) {
	f := checkRule(t, GL054, `
build:
  services: [docker:27-dind]
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      variables:
        DOCKER_HOST: tcp://docker:2375
  script: [docker build .]
`)
	if len(f) != 1 || !strings.Contains(f[0].Message, "service") {
		t.Errorf("expected only the service finding, got %v", f)
	}
}
