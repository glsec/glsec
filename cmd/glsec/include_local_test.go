// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const includedBuild = "build:\n  image: python:latest\n  script: [make]\n"

// scanIncludes runs a JSON scan of .gitlab-ci.yml and returns "file rule"
// for each finding, sorted, and stderr.
func scanIncludes(t *testing.T, files map[string]string, args ...string) ([]string, string) {
	t.Helper()
	if len(args) == 0 {
		args = []string{".gitlab-ci.yml"}
	}
	_, stdout, stderr := runCLI(t, files, append([]string{"--format", "json"}, args...)...)
	var report struct {
		Findings []struct{ Rule, File string }
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("%v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	var got []string
	for _, f := range report.Findings {
		got = append(got, filepath.ToSlash(f.File)+" "+f.Rule)
	}
	sort.Strings(got)
	return got, stderr
}

func hasFinding(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}

func TestIncludeLocal_Followed(t *testing.T) {
	for name, include := range map[string]string{
		"list of local":  "include:\n  - local: ci/build.yml\n",
		"single mapping": "include:\n  local: ci/build.yml\n",
		"string":         "include: ci/build.yml\n",
		"list of string": "include:\n  - ci/build.yml\n",
		"leading slash":  "include:\n  - local: /ci/build.yml\n",
		"with rules":     "include:\n  - local: ci/build.yml\n    rules:\n      - if: $CI_COMMIT_TAG\n",
		"wildcard":       "include:\n  - local: ci/*.yml\n",
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := scanIncludes(t, map[string]string{".gitlab-ci.yml": include, "ci/build.yml": includedBuild})
			if !hasFinding(got, "ci/build.yml GL001") {
				t.Errorf("GL001 in ci/build.yml not reported: %v", got)
			}
			// The included file is part of the root's pipeline, not one of
			// its own: a missing workflow: is reported once, on the root.
			if hasFinding(got, "ci/build.yml GL053") || !hasFinding(got, ".gitlab-ci.yml GL053") {
				t.Errorf("GL053 should be on the root only: %v", got)
			}
		})
	}
}

func TestIncludeLocal_Wildcards(t *testing.T) {
	files := map[string]string{
		"ci/a.yml":        "a:\n  image: a:latest\n  script: [x]\n",
		"ci/sub/b.yml":    "b:\n  image: b:latest\n  script: [x]\n",
		"ci/c.yaml":       "c:\n  image: c:latest\n  script: [x]\n",
		"ci/notes.txt":    "not a pipeline",
		".git/ci/d.yml":   "d:\n  image: d:latest\n  script: [x]\n",
		"other/e.yml":     "e:\n  image: e:latest\n  script: [x]\n",
		"ci/sub/deep.yml": "deep:\n  image: f:latest\n  script: [x]\n",
	}
	for _, tc := range []struct {
		pattern string
		want    []string
	}{
		{"ci/*.yml", []string{"ci/a.yml"}},
		{"ci/**.yml", []string{"ci/a.yml", "ci/sub/b.yml", "ci/sub/deep.yml"}},
		{"ci/**/*.yml", []string{"ci/a.yml", "ci/sub/b.yml", "ci/sub/deep.yml"}},
		{"ci/*.{yml,yaml}", []string{"ci/a.yml", "ci/c.yaml"}},
		{"ci/sub/?.yml", []string{"ci/sub/b.yml"}},
		{"**/d.yml", nil},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			f := map[string]string{".gitlab-ci.yml": "include:\n  - local: '" + tc.pattern + "'\n"}
			for k, v := range files {
				f[k] = v
			}
			got, stderr := scanIncludes(t, f)
			var scanned []string
			for _, g := range got {
				if file, rule, _ := strings.Cut(g, " "); rule == "GL001" {
					scanned = append(scanned, file)
				}
			}
			if strings.Join(scanned, ",") != strings.Join(tc.want, ",") {
				t.Errorf("scanned %v, want %v; stderr:\n%s", scanned, tc.want, stderr)
			}
		})
	}
}

func TestIncludeLocal_NestedAndCycles(t *testing.T) {
	got, stderr := scanIncludes(t, map[string]string{
		".gitlab-ci.yml": "include: ci/a.yml\n",
		"ci/a.yml":       "include:\n  - ci/a.yml\n  - ci/b.yml\na:\n  image: a:latest\n  script: [x]\n",
		"ci/b.yml":       "include: [.gitlab-ci.yml, ci/a.yml]\nb:\n  image: b:latest\n  script: [x]\n",
	})
	if !hasFinding(got, "ci/a.yml GL001") || !hasFinding(got, "ci/b.yml GL001") {
		t.Errorf("nested includes not scanned: %v; stderr:\n%s", got, stderr)
	}
	if n := strings.Count(strings.Join(got, "\n"), "ci/a.yml GL001"); n != 1 {
		t.Errorf("ci/a.yml reported %d times, want once: %v", n, got)
	}
}

func TestIncludeLocal_Skipped(t *testing.T) {
	got, stderr := scanIncludes(t, map[string]string{
		".gitlab-ci.yml": "include:\n  - local: ci/missing.yml\n  - local: ../outside.yml\n  - local: ci/$ENVIRONMENT.yml\n  - local: '$[[ inputs.file ]]'\n  - remote: https://example.com/ci.yml\n  - project: group/project\n    file: ci.yml\n  - component: gitlab.com/group/component@1.0\n",
		"ci/prod.yml":    includedBuild,
	})
	if !strings.Contains(stderr, "warning: include ci/missing.yml:") {
		t.Errorf("no warning for the missing file:\n%s", stderr)
	}
	if !strings.Contains(stderr, "outside the repository, skipped") {
		t.Errorf("no warning for the file outside the repository:\n%s", stderr)
	}
	if hasFinding(got, "ci/prod.yml GL001") {
		t.Errorf("a path with a variable was resolved: %v", got)
	}
}

func TestIncludeLocal_Excluded(t *testing.T) {
	got, _ := scanIncludes(t, map[string]string{
		".gitlab-ci.yml": "include: ci/build.yml\n",
		"ci/build.yml":   includedBuild,
	}, "--exclude", "ci/*", ".gitlab-ci.yml")
	if hasFinding(got, "ci/build.yml GL001") {
		t.Errorf("excluded include scanned: %v", got)
	}
}

// GitLab merges the included files into one configuration, so the rules see
// the root's workflow:, default: and templates in an included file, and the
// other way round.
func TestIncludeLocal_PipelineContext(t *testing.T) {
	t.Run("workflow and default of the root", func(t *testing.T) {
		got, _ := scanIncludes(t, map[string]string{
			".gitlab-ci.yml": "workflow:\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"push\"\ndefault:\n  image: node:latest\n  tags: [docker]\ninclude: ci/deploy.yml\n",
			"ci/deploy.yml":  "deploy:\n  stage: deploy\n  resource_group: prod\n  script: [./deploy.sh]\n",
		})
		for _, rule := range []string{"GL080", "GL017", "GL001"} {
			if hasFinding(got, "ci/deploy.yml "+rule) {
				t.Errorf("%s reported in ci/deploy.yml despite the root's configuration: %v", rule, got)
			}
		}
		// The default image is reported where it is, once.
		if n := strings.Count(strings.Join(got, "\n"), "GL001"); n != 1 || !hasFinding(got, ".gitlab-ci.yml GL001") {
			t.Errorf("want GL001 once on the root: %v", got)
		}
	})
	t.Run("workflow in an included file", func(t *testing.T) {
		got, _ := scanIncludes(t, map[string]string{
			".gitlab-ci.yml":  "include: ci/workflow.yml\nbuild:\n  image: alpine:3.20\n  script: [make]\n",
			"ci/workflow.yml": "workflow:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n",
		})
		if hasFinding(got, ".gitlab-ci.yml GL053") {
			t.Errorf("GL053 on the root although an included file has workflow: %v", got)
		}
	})
}

// The workaround before #810 was to name the included files too. A file
// scanned as part of the pipeline isn't scanned again on its own.
func TestIncludeLocal_NamedToo(t *testing.T) {
	got, _ := scanIncludes(t, map[string]string{
		".gitlab-ci.yml": "include: ci/build.yml\n",
		"ci/build.yml":   includedBuild,
	}, ".gitlab-ci.yml", "ci/build.yml")
	if strings.Count(strings.Join(got, "\n"), "ci/build.yml") != 1 {
		t.Errorf("want ci/build.yml's GL001 once and no GL053: %v", got)
	}
}

// Files glsec finds itself are joined with the OS separator; the reports
// write them with / also on Windows (#956).
func TestRun_IncludedFileReportedWithSlashes(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "include:\n  - local: ci/jobs.yml\n",
		"ci/jobs.yml":    includedBuild,
	}
	for _, format := range []string{"json", "sarif"} {
		_, out, stderr := runCLI(t, files, "--no-cache", "--only", "GL001", "--format", format)
		if !strings.Contains(out, `"ci/jobs.yml"`) {
			t.Errorf("%s: included file not reported as ci/jobs.yml: %s (stderr %s)", format, out, stderr)
		}
	}
}
