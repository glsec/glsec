package main

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type jsonFinding struct {
	Rule string `json:"rule"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// gl001Files runs a JSON scan and returns, sorted, the files that have a GL001
// finding: the child fixtures each carry one mutable image tag.
func gl001Files(t *testing.T, files map[string]string, args ...string) (code int, got []string, stderr string) {
	t.Helper()
	code, stdout, stderr := runCLI(t, files, append([]string{"--format", "json", "--only", "GL001"}, args...)...)
	var out struct {
		Findings []jsonFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, stdout)
	}
	for _, f := range out.Findings {
		got = append(got, filepath.ToSlash(f.File))
	}
	sort.Strings(got)
	return code, got, stderr
}

const (
	childJob = `child-job:
  image: node:latest
  script: [echo]
`
	grandJob = `grand-job:
  image: python:latest
  script: [echo]
`
)

func TestChildPipelines_Nested(t *testing.T) {
	// GitLab resolves trigger:include paths from the repository root, also
	// inside a child that lives in a subdirectory.
	files := map[string]string{
		".gitlab-ci.yml": "trigger-child:\n  trigger:\n    include: ci/child.yml\n",
		"ci/child.yml":   childJob + "trigger-grand:\n  trigger:\n    include:\n      - local: ci/grand.yml\n",
		"ci/grand.yml":   grandJob,
	}
	code, got, stderr := gl001Files(t, files)
	want := []string{"ci/child.yml", "ci/grand.yml"}
	if code != 1 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("exit %d, GL001 in %v, want %v; stderr:\n%s", code, got, want, stderr)
	}
}

func TestChildPipelines_LeadingSlashAndMappingForm(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "a:\n  trigger:\n    include: /ci/child.yml\nb:\n  trigger:\n    include:\n      local: ci/grand.yml\n",
		"ci/child.yml":   childJob,
		"ci/grand.yml":   grandJob,
	}
	_, got, stderr := gl001Files(t, files)
	want := []string{"ci/child.yml", "ci/grand.yml"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("GL001 in %v, want %v; stderr:\n%s", got, want, stderr)
	}
}

func TestChildPipelines_CycleAndDuplicate(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "a:\n  trigger:\n    include: ci/child.yml\nb:\n  trigger:\n    include: ci/child.yml\n",
		"ci/child.yml":   childJob + "back:\n  trigger:\n    include: .gitlab-ci.yml\n",
	}
	code, got, _ := gl001Files(t, files)
	if code != 1 || len(got) != 1 || got[0] != "ci/child.yml" {
		t.Fatalf("a child included twice and a cycle back to the root should give one finding, got exit %d, %v", code, got)
	}
}

func TestChildPipelines_ExcludedChild(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "a:\n  trigger:\n    include: ci/child.yml\n",
		"ci/child.yml":   childJob,
	}
	code, got, _ := gl001Files(t, files, "--exclude", "ci/")
	if code != 0 || len(got) != 0 {
		t.Fatalf("an excluded child must not be scanned, got exit %d, %v", code, got)
	}
}

func TestChildPipelines_MissingOrBrokenChildWarns(t *testing.T) {
	files := map[string]string{
		".gitlab-ci.yml": "a:\n  trigger:\n    include: ci/missing.yml\nb:\n  trigger:\n    include: ci/broken.yml\nc:\n  trigger:\n    include: ci/child.yml\n",
		"ci/broken.yml":  "job: [unclosed\n",
		"ci/child.yml":   childJob,
	}
	code, got, stderr := gl001Files(t, files)
	if code != 1 || len(got) != 1 || got[0] != "ci/child.yml" {
		t.Fatalf("a missing or broken child must not stop the scan, got exit %d, %v", code, got)
	}
	for _, want := range []string{"child pipeline ci/missing.yml", "child pipeline ci/broken.yml"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestChildPipelines_RootInSubdirectory(t *testing.T) {
	// Scanning a pipeline outside the working directory resolves its children
	// from that pipeline's directory.
	files := map[string]string{
		"repo/.gitlab-ci.yml": "a:\n  trigger:\n    include: ci/child.yml\n",
		"repo/ci/child.yml":   childJob,
	}
	_, got, stderr := gl001Files(t, files, "repo/.gitlab-ci.yml")
	if len(got) != 1 || got[0] != "repo/ci/child.yml" {
		t.Fatalf("GL001 in %v, want [repo/ci/child.yml]; stderr:\n%s", got, stderr)
	}
}
