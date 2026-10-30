// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRunInventory(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": "job:\n  image: node:20.11.0\n  script: [x]\n", "other.yml": "include:\n  - component: gitlab.com/g/p/c@1.2.3\n"}

	code, stdout, stderr := runCLI(t, files, "inventory")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Metadata   struct{ Component struct{ Name string } }
		Components []struct {
			BOMRef string `json:"bom-ref"`
			PURL   string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(stdout), &bom); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if bom.BOMFormat != "CycloneDX" || bom.Metadata.Component.Name != ".gitlab-ci.yml" || len(bom.Components) != 1 || bom.Components[0].PURL != "pkg:docker/library/node@20.11.0" {
		t.Errorf("BOM = %+v", bom)
	}

	if code, stdout, _ := runCLI(t, files, "inventory", "--format", "cyclonedx", "other.yml"); code != 0 || !strings.Contains(stdout, `"component:gitlab.com/g/p/c@1.2.3"`) {
		t.Errorf("explicit file: exit %d\n%s", code, stdout)
	}
}

// --format jobs lists the visible jobs of the scanned document: no hidden
// templates, no top-level keywords, the body after a spec: header (#930).
func TestRunInventory_Jobs(t *testing.T) {
	src := "spec:\n  inputs: {}\n---\nstages: [a]\n.tpl:\n  image: alpine:3.20.3\nbuild:\n  extends: .tpl\n  script: [x]\npages:\n  script: [x]\n"
	code, stdout, stderr := runCLI(t, map[string]string{".gitlab-ci.yml": src}, "inventory", "--format", "jobs")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var out struct {
		Jobs []struct {
			Name string `json:"name"`
			Line int    `json:"line"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	if len(out.Jobs) != 2 || out.Jobs[0].Name != "build" || out.Jobs[0].Line != 7 || out.Jobs[1].Name != "pages" {
		t.Errorf("jobs = %+v, want build (line 7) and pages", out.Jobs)
	}

	if _, stdout, _ := runCLI(t, map[string]string{".gitlab-ci.yml": "stages: [a]\n"}, "inventory", "--format", "jobs"); !strings.Contains(stdout, `"jobs": []`) {
		t.Errorf("a file without jobs must give an empty list, got %s", stdout)
	}
}

func TestRunInventory_Errors(t *testing.T) {
	files := map[string]string{".gitlab-ci.yml": "job:\n  script: [x]\n"}
	for _, args := range [][]string{
		{"inventory", "--format", "spdx"},
		{"inventory", "missing.yml"},
		{"inventory", "a.yml", "b.yml"},
		{"inventory", "--no-such-flag"},
	} {
		if code, _, _ := runCLI(t, files, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := runCLI(t, files, "inventory", "-h"); code != 0 {
		t.Errorf("-h: exit %d, want 0", code)
	}
	if code, _, _ := runCLI(t, map[string]string{".gitlab-ci.yml": "job: [unclosed\n"}, "inventory"); code != 2 {
		t.Errorf("broken YAML: exit %d, want 2", code)
	}
}
