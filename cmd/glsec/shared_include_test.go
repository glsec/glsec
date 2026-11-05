// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func twoChildren(first, second string) string {
	return "child_" + first + ":\n  trigger:\n    include: " + first + ".yml\nchild_" + second + ":\n  trigger:\n    include: " + second + ".yml\n"
}

func deployChild(name string) string {
	return "include: shared.yml\ndeploy_" + name + ":\n  environment: production\n  script: [echo deploy]\n"
}

const sharedWorkflow = "workflow:\n  rules:\n    - if: $CI_COMMIT_REF_PROTECTED == \"true\"\n"

// A file belongs to every pipeline that includes it, so each child gets its
// workflow: guard, whichever comes first (#1166).
func TestRun_FileSharedByChildPipelines(t *testing.T) {
	files := func(root string) map[string]string {
		return map[string]string{"root.yml": root, "a.yml": deployChild("a"), "b.yml": deployChild("b"), "shared.yml": sharedWorkflow}
	}
	code, ab, stderr := runCLI(t, files(twoChildren("a", "b")), "--no-cache", "--only", "GL013", "--format", "json", "root.yml")
	if code != 0 || strings.Contains(ab, `"rule": "GL013"`) {
		t.Fatalf("exit %d, stderr %s:\n%s", code, stderr, ab)
	}
	_, ba, _ := runCLI(t, files(twoChildren("b", "a")), "--no-cache", "--only", "GL013", "--format", "json", "root.yml")
	if ab != ba {
		t.Errorf("the order of independent child pipelines changed the report:\n%s\nvs\n%s", ab, ba)
	}
}

func TestRun_SharedFileFindingIsReportedOnce(t *testing.T) {
	files := map[string]string{
		"root.yml":   twoChildren("a", "b"),
		"a.yml":      deployChild("a"),
		"b.yml":      deployChild("b"),
		"shared.yml": "shared:\n  image: node:latest\n  script: [make]\n",
	}
	code, out, _ := runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "json", "root.yml")
	if code != 1 || strings.Count(out, `"rule": "GL001"`) != 1 {
		t.Fatalf("exit %d, want 1 and one finding:\n%s", code, out)
	}
}

// Each file counts once, however many pipelines include it.
func TestRun_SharedFileCountsOnce(t *testing.T) {
	files := map[string]string{
		"root.yml":   twoChildren("a", "b"),
		"a.yml":      "include: shared.yml\n",
		"b.yml":      "include: shared.yml\n",
		"shared.yml": "shared:\n  script: [make]\n  image: alpine:3.20\n",
		"count.tmpl": "{{.Summary.Files}} files, {{.Summary.Jobs}} jobs\n",
	}
	_, out, _ := runCLI(t, files, "--no-cache", "--only", "GL001", "--format", "template", "--template", "count.tmpl", "root.yml")
	if !strings.Contains(out, "4 files, 3 jobs") {
		t.Errorf("want 4 files and 3 jobs, the two triggers and shared: %s", out)
	}

	files["shared.yml"] = "shared:\n  image: node:latest # glsec:ignore GL001\n  script: [make]\n"
	files[".glsec.yml"] = "require_ignore_reason: true\n"
	code, _, stderr := runCLI(t, files, "--no-cache", "--only", "GL001", "root.yml")
	if code != 2 || !strings.Contains(stderr, "1 suppression(s) without a reason") {
		t.Fatalf("exit %d, want 2 and one complaint:\n%s", code, stderr)
	}
}

func TestRun_SharedFileProblemIsReportedOnce(t *testing.T) {
	files := map[string]string{
		"root.yml": twoChildren("a", "b"),
		"a.yml":    "include:\n  - missing.yml\n  - ../outside.yml\n",
		"b.yml":    "include:\n  - missing.yml\n  - ../outside.yml\n",
	}
	_, _, stderr := runCLI(t, files, "--no-cache", "--only", "GL001", "root.yml")
	if strings.Count(stderr, "warning: include missing.yml") != 1 || strings.Count(stderr, "outside the repository") != 1 {
		t.Errorf("want each warning once:\n%s", stderr)
	}
}

func TestRun_IncludeCyclesEnd(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"include": {
			"root.yml": "include: a.yml\njob:\n  script: [make]\n",
			"a.yml":    "include: b.yml\n",
			"b.yml":    "include: a.yml\n",
		},
		"include of the root": {
			"root.yml": "include: root.yml\njob:\n  script: [make]\n",
		},
		"child pipelines": {
			"root.yml": "c:\n  trigger:\n    include: a.yml\n",
			"a.yml":    "c:\n  trigger:\n    include: b.yml\n",
			"b.yml":    "c:\n  trigger:\n    include: a.yml\n",
		},
		"child includes its parent": {
			"root.yml": "c:\n  trigger:\n    include: a.yml\n",
			"a.yml":    "include: root.yml\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if code, out, stderr := runCLI(t, files, "--no-cache", "--only", "GL001", "root.yml"); code != 0 {
				t.Fatalf("exit %d:\n%s\n%s", code, out, stderr)
			}
		})
	}
}
