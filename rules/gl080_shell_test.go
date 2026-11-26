// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

func parseTestYAML(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	return parser.Unwrap(&doc)
}

func variableText(job *yaml.Node, name string) string {
	if v := parser.FindKey(parser.FindKey(job, "variables"), name); v != nil {
		return v.Value
	}
	return ""
}

func TestRefTest(t *testing.T) {
	for cond, want := range map[string]int{
		`[ "$CI_COMMIT_BRANCH" = "main" ]`:                 1,
		`[[ $CI_COMMIT_REF_NAME == $CI_DEFAULT_BRANCH ]]`:  0,
		`[ "$CI_DEFAULT_BRANCH" = "${CI_COMMIT_BRANCH}" ]`: 1,
		`test "$CI_COMMIT_REF_PROTECTED" = true`:           1,
		`[ "$CI_COMMIT_REF_PROTECTED" != "false" ]`:        1,
		`[ -n "$CI_COMMIT_TAG" ]`:                          1,
		`[ "$CI_COMMIT_TAG" != "" ]`:                       1,
		`! [ -z "$CI_COMMIT_TAG" ]`:                        1,
		`[ "$CI_COMMIT_BRANCH" != "main" ]`:                -1,
		`[ "$CI_COMMIT_REF_PROTECTED" = "false" ]`:         -1,
		`[ -z "$CI_COMMIT_TAG" ]`:                          -1,
		`[ "$CI_COMMIT_TAG" = "" ]`:                        -1,
		`! [ "$CI_COMMIT_BRANCH" = main ]`:                 -1,
		`[[ "$CI_COMMIT_BRANCH" == release* ]]`:            0,
		`[ "$CI_COMMIT_BRANCH" = "$TARGET" ]`:              0,
		`[ "$PUSH" = "yes" ]`:                              0,
		`[ "$CI_COMMIT_REF_PROTECTED" = maybe ]`:           0,
		`[ "$CI_COMMIT_TAG" = "v1" ]`:                      0,
		`[ -n "$CI_COMMIT_BRANCH" ]`:                       0,
		`[ -n $CI_COMMIT_TAG ]`:                            0,
		`[[ -n $CI_COMMIT_TAG ]]`:                          1,
		`[ $CI_COMMIT_BRANCH = main ]`:                     1,
		`[ $CI_COMMIT_BRANCH != main ]`:                    0,
		`[ "$CI_COMMIT_BRANCH" -eq 1 ]`:                    0,
		`[ "$CI_COMMIT_BRANCH" = main ] && [ "$X" ]`:       0,
		`grep -q x file`:                                   0,
	} {
		if got := refTest(cond); got != want {
			t.Errorf("refTest(%q) = %d, want %d", cond, got, want)
		}
	}
}

func TestExitGuardAt(t *testing.T) {
	for text, want := range map[string]bool{
		`if [ "$CI_COMMIT_BRANCH" != "$CI_DEFAULT_BRANCH" ]; then exit 0; fi`: true,
		`[ -n "$CI_COMMIT_TAG" ] || exit 0`:                                   true,
		`[ -z "$CI_COMMIT_TAG" ] && exit 0`:                                   true,
		`if [ "$CI_COMMIT_BRANCH" = main ]; then exit 0; fi`:                  false,
		`[ "$CI_COMMIT_BRANCH" = main ] && exit 0`:                            false,
		`[ -n "$SKIP" ] && exit 0`:                                            false,
		`exit 0`:                                                              false,
		`(if [ "$CI_COMMIT_BRANCH" != main ]; then exit 0; fi)`:               false,
		`sh -c '[ "$CI_COMMIT_BRANCH" = main ] || exit 0'`:                    false,
		`skip() { [ "$CI_COMMIT_BRANCH" = main ] || exit 0; }`:                false,
		`if [ -f skip ]; then [ "$CI_COMMIT_BRANCH" = main ] || exit 0; fi`:   false,
		`# if [ "$CI_COMMIT_BRANCH" != "main" ]; then exit 0; fi`:             false,
		`echo 'if [ "$CI_COMMIT_BRANCH" != main ]; then exit 0; fi' > c.sh`:   false,
		`if [ $CI_COMMIT_BRANCH != main ]; then exit 0; fi`:                   false,
		`[ $CI_COMMIT_BRANCH = main ] || exit 0`:                              true,
		`true || [ -n "$CI_COMMIT_TAG" ] || exit 0`:                           false,
	} {
		if got := exitGuardAt(text) >= 0; got != want {
			t.Errorf("exitGuardAt(%q) >= 0 = %v, want %v", text, got, want)
		}
	}
}

func TestStripShellKeywords(t *testing.T) {
	for in, want := range map[string]string{
		"then   else X=1": "X=1",
		"do X=1":          "X=1",
		"thenX=1":         "thenX=1",
		"  Y=2":           "Y=2",
	} {
		if got := stripShellKeywords(in); got != want {
			t.Errorf("stripShellKeywords(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTopLevel(t *testing.T) {
	for s, want := range map[string]bool{
		"X":                            true,
		"case $a in x) ;; esac; X":     true,
		"for i in 1; do echo; done; X": true,
		"if a; then b; fi; X":          true,
		`echo "a\"b"; X`:               true,
		`echo a\ b; X`:                 true,
		"iffy; X":                      true,
		"if_x; X":                      true,
		"{ a; }; X":                    true,
		"while true; do X":             false,
		"case $a in x) X":              false,
		"{ X":                          false,
		`echo "X`:                      false,
	} {
		if got := topLevel(s, strings.Index(s, "X")); got != want {
			t.Errorf("topLevel(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestExitGuardOrder(t *testing.T) {
	text := `[ -n "$CI_COMMIT_TAG" ] || exit 0; if [ "$CI_COMMIT_BRANCH" != main ]; then exit 0; fi`
	if got := exitGuardAt(text); got != 0 {
		t.Errorf("exitGuardAt(%q) = %d, want 0", text, got)
	}
	text = `if [ "$CI_COMMIT_BRANCH" != main ]; then exit 0; fi; [ -n "$CI_COMMIT_TAG" ] || exit 0`
	if got := exitGuardAt(text); got != 0 {
		t.Errorf("exitGuardAt(%q) = %d, want 0", text, got)
	}
	if got := refTest(`[ -x "$CI_COMMIT_TAG" ]`); got != 0 {
		t.Errorf("refTest(-x) = %d, want 0", got)
	}
}

func TestBlankGuardedStepsOrList(t *testing.T) {
	text := `[ -f x ] || [ "$CI_COMMIT_BRANCH" = main ] && docker push app:latest`
	if got := blankGuardedSteps(text); got != text {
		t.Errorf("blankGuardedSteps(%q) = %q, want it unchanged", text, got)
	}
}

func TestWithEntryVariables(t *testing.T) {
	job := parseTestYAML(t, "variables:\n  A: job\n  B: job\nscript: [x]\n")
	entry := parseTestYAML(t, "variables:\n  B: entry\n")
	got := withEntryVariables(job, entry)
	if v := variableText(got, "A"); v != "job" {
		t.Errorf("A = %q, want job", v)
	}
	if v := variableText(got, "B"); v != "entry" {
		t.Errorf("B = %q, want entry", v)
	}
	if v := variableText(job, "B"); v != "job" {
		t.Errorf("the job itself changed: B = %q", v)
	}
	if same := withEntryVariables(job, parseTestYAML(t, "when: manual\n")); same != job {
		t.Error("an entry without variables: should return the job")
	}
}

func TestServiceHostsAndPublish(t *testing.T) {
	job := parseTestYAML(t, "services:\n  - postgres:16\n  - alias: bare\n  - name: registry.example/team/app:1\n    alias: api, web\nscript: [x]\n")
	hosts := serviceHosts(job)
	for _, h := range []string{"postgres", "app", "api", "web", "localhost"} {
		if !hosts[h] {
			t.Errorf("serviceHosts lacks %q: %v", h, hosts)
		}
	}
	if serviceHosts(parseTestYAML(t, "script: [x]\n")) != nil {
		t.Error("no services: want nil")
	}
	lines := func(ls ...string) []*yaml.Node {
		var out []*yaml.Node
		for _, l := range ls {
			out = append(out, &yaml.Node{Kind: yaml.ScalarNode, Value: l})
		}
		return out
	}
	for _, tc := range []struct {
		line  string
		lines []*yaml.Node
		want  bool
	}{
		{"tool publish --url http://api:9999", nil, true},
		{"tool publish --url http://api:9999 --mirror https://cdn.example.com", nil, false},
		{"tool publish", lines("tool config set remote http://web:8080"), true},
		{"tool publish", lines("curl http://localhost:8080/health"), false},
		{"tool publish", lines("tool config set remote http://web:8080", "curl https://example.com"), false},
	} {
		if got := publishesToService(job, tc.line, tc.lines, hosts); got != tc.want {
			t.Errorf("publishesToService(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
	if publishesToService(job, "tool publish", nil, nil) {
		t.Error("no services: want false")
	}
}

func TestEphemeralImagePushOperands(t *testing.T) {
	for cmd, want := range map[string]bool{
		"docker image push app:$CI_COMMIT_SHA":                  true,
		"nerdctl push app:$CI_PIPELINE_ID":                      true,
		"docker push -q app:$CI_COMMIT_SHA":                     true,
		"docker push":                                           false,
		"docker pull app:$CI_COMMIT_SHA":                        false,
		"docker image ls":                                       false,
		"kubectl push x":                                        false,
		"podman push app:$CI_COMMIT_SHA reg/app:$CI_COMMIT_SHA": true,
		"podman push app:$CI_COMMIT_SHA reg/app:latest":         false,
	} {
		if got := ephemeralImagePush(commandWords(cmd), nil, nil, nil); got != want {
			t.Errorf("ephemeralImagePush(%q) = %v, want %v", cmd, got, want)
		}
	}
	multi := map[string][]string{"T": {"$CI_COMMIT_SHA", "$CI_PIPELINE_ID"}}
	if !ephemeralImagePush(commandWords("docker push app:$T"), nil, nil, multi) {
		t.Error("every value per run: want true")
	}
}

func TestEphemeralEnvironmentUnresolved(t *testing.T) {
	env := &yaml.Node{Kind: yaml.ScalarNode, Value: "$UNSET_ENV"}
	vars := parseTestYAML(t, "OTHER: x\n")
	if ephemeralEnvironmentIn(env, vars, nil) {
		t.Error("an unresolved name: want false")
	}
	if !clusterCommand(commandWords("kubectl apply -f x")) || clusterCommand(commandWords("docker push x")) {
		t.Error("clusterCommand")
	}
}
