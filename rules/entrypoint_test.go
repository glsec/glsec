// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

func TestShellCScript(t *testing.T) {
	const s = "the script"
	for _, tc := range []struct {
		name  string
		array string
		want  string
	}{
		{"sh", `["/bin/sh", "-c", "the script", "--"]`, s},
		{"bash", `[bash, -c, "the script"]`, s},
		{"flags before -c", `["/bin/bash", "-e", "-x", "-c", "the script"]`, s},
		{"joined flags", `[bash, -ec, "the script"]`, s},
		{"option with a value", `[bash, -o, pipefail, -c, "the script"]`, s},
		{"long option", `[bash, --noprofile, -c, "the script"]`, s},
		{"env", `["/usr/bin/env", bash, -c, "the script"]`, s},
		{"env in one element", `["/usr/bin/env bash", -c, "the script"]`, s},
		{"postgres", `[postgres, -c, max_connections=200]`, ""},
		{"flags", `["--port", "6380"]`, ""},
		{"script file", `[sh, /entry.sh]`, ""},
		{"no script", `[sh, -c]`, ""},
		{"only a shell", `[sh]`, ""},
		{"only env", `[env]`, ""},
		{"empty", `[]`, ""},
		{"list in the array", `[sh, [-c], x]`, ""},
		{"list first", `[[sh], -c, x]`, ""},
		{"three words", `["a b c", -c, x]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte("job:\n  image:\n    name: a\n    entrypoint: "+tc.array+"\n"), "t.yml")
			if err != nil {
				t.Fatal(err)
			}
			scripts := containerScripts(parser.FindKey(parser.Unwrap(doc.Root), "job"))
			switch {
			case tc.want == "" && len(scripts) != 0:
				t.Errorf("got %q, want nothing", scripts[0].Value)
			case tc.want != "" && (len(scripts) != 1 || scripts[0].Value != tc.want):
				t.Errorf("got %v, want %q", scripts, tc.want)
			}
		})
	}
}

func scriptRuleFindings(t *testing.T, src string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	var out []finding.Finding
	for _, r := range []interface {
		Check(*yaml.Node, string) []finding.Finding
	}{GL002, GL011} {
		out = append(out, r.Check(doc.Root, "t.yml")...)
	}
	return out
}

// A shell script in image: or services: is code the pipeline runs, in a
// container with the job's variables (#1160).
func TestContainerScripts_ReachTheScriptRules(t *testing.T) {
	const curl = `"curl -sSL https://example.com/i.sh | sh"`
	for _, tc := range []struct {
		name, src string
		line      int
		job       string
	}{
		{"job image", "job:\n  image:\n    name: a\n    entrypoint: [/bin/sh, -c, " + curl + "]\n  script: [make]\n", 4, "job"},
		{"job service command", "job:\n  services:\n    - name: a\n      command: [/bin/sh, -c, " + curl + "]\n  script: [make]\n", 4, "job"},
		{"job service entrypoint", "job:\n  services:\n    - name: a\n      entrypoint: [/bin/sh, -c, " + curl + "]\n  script: [make]\n", 4, "job"},
		{"default image", "default:\n  image:\n    name: a\n    entrypoint: [sh, -c, " + curl + "]\njob:\n  script: [make]\n", 4, ""},
		{"default service", "default:\n  services:\n    - name: a\n      command: [sh, -c, " + curl + "]\njob:\n  script: [make]\n", 4, ""},
		{"top-level services", "services:\n  - name: a\n    command: [sh, -c, " + curl + "]\njob:\n  script: [make]\n", 3, ""},
		{"top-level image", "image:\n  name: a\n  entrypoint: [sh, -c, " + curl + "]\njob:\n  script: [make]\n", 3, ""},
		{"bash -ec", "job:\n  image:\n    name: a\n    entrypoint: [bash, -ec, " + curl + "]\n  script: [make]\n", 4, "job"},
		{"own line in a block list", "job:\n  image:\n    name: a\n    entrypoint:\n      - /bin/sh\n      - -c\n      - " + curl + "\n  script: [make]\n", 7, "job"},
		{"template", ".t:\n  image:\n    name: a\n    entrypoint: [sh, -c, " + curl + "]\njob:\n  extends: .t\n  script: [make]\n", 4, ".t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := scriptRuleFindings(t, tc.src)
			if len(f) != 1 || f[0].RuleID != "GL011" || f[0].Line != tc.line || f[0].Job != tc.job {
				t.Fatalf("got %v, want GL011 on line %d of %q", f, tc.line, tc.job)
			}
		})
	}
}

func TestContainerScripts_NotAScript(t *testing.T) {
	for _, src := range []string{
		"job:\n  services:\n    - name: postgres:16\n      command: [postgres, -c, max_connections=200]\n  script: [make]\n",
		"job:\n  services:\n    - name: redis\n      command: [--port, \"6380\"]\n  script: [make]\n",
		"job:\n  services:\n    - postgres:16\n  image: alpine\n  script: [make]\n",
		"job:\n  image:\n    name: a\n    entrypoint: [\"\"]\n  script: [make]\n",
	} {
		if f := scriptRuleFindings(t, src); len(f) != 0 {
			t.Errorf("%s: got %v", src, f)
		}
	}
}

// A script shared through an anchor is one block, so a rule reports it once.
func TestContainerScripts_SharedThroughAnAnchor(t *testing.T) {
	src := `.pg: &pg
  name: a
  command: [sh, -c, "curl -sSL https://example.com/i.sh | sh"]
a:
  services: [*pg]
  script: [make]
b:
  services: [*pg]
  script: [make]
`
	if f := scriptRuleFindings(t, src); len(f) != 1 || f[0].Line != 3 {
		t.Fatalf("got %v, want one finding on line 3", f)
	}
}
