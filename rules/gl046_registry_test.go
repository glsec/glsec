// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// A registry build cache with a fixed reference is shared by every branch;
// GitLab's protected-cache separation covers cache: only (#1500).
func TestGL046_RegistryBuildCache(t *testing.T) {
	kaniko := "/kaniko/executor --context . --destination \"$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA\""
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"kaniko cache, fixed repo", "build:\n  script:\n    - " + kaniko + " --cache=true --cache-repo \"$CI_REGISTRY_IMAGE/cache\"\n", 1},
		{"kaniko cache, default repo", "build:\n  script:\n    - " + kaniko + " --cache\n", 1},
		{"kaniko cache-repo=", "build:\n  script:\n    - " + kaniko + " --cache=true --cache-repo=$CI_REGISTRY_IMAGE/cache\n", 1},
		{"kaniko without cache", "build:\n  script:\n    - " + kaniko + "\n", 0},
		{"kaniko per-branch cache repo", "build:\n  script:\n    - " + kaniko + " --cache=true --cache-repo $CI_REGISTRY_IMAGE/cache/$CI_COMMIT_REF_SLUG\n", 0},
		{"buildx registry cache", `
build:
  script:
    - docker buildx build --push -t "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
      --cache-to "type=registry,ref=$CI_REGISTRY_IMAGE/cache-image,mode=max"
      --cache-from "type=registry,ref=$CI_REGISTRY_IMAGE/cache-image" .
`, 1},
		{"buildx cache-to=", "build:\n  script:\n    - docker buildx build --cache-to=type=registry,ref=registry.example.com/app:buildcache .\n", 1},
		{"buildctl export-cache", "build:\n  script:\n    - buildctl build --frontend dockerfile.v0 --export-cache type=registry,ref=$CI_REGISTRY_IMAGE:cache\n", 1},
		{"buildx per-branch ref", "build:\n  script:\n    - docker buildx build --cache-to type=registry,ref=$CI_REGISTRY_IMAGE/cache:${CI_COMMIT_REF_SLUG} .\n", 0},
		{"cache-from only", "build:\n  script:\n    - docker buildx build --cache-from type=registry,ref=$CI_REGISTRY_IMAGE/cache .\n", 0},
		{"inline cache", "build:\n  script:\n    - docker buildx build --cache-to type=inline -t app .\n", 0},
		{"gha cache", "build:\n  script:\n    - docker buildx build --cache-to type=gha .\n", 0},
		{"default branch only", "build:\n  rules:\n    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n  script:\n    - " + kaniko + " --cache\n", 0},
		{"protected-only workflow", "workflow:\n  rules:\n    - if: $CI_COMMIT_TAG\nbuild:\n  script:\n    - " + kaniko + " --cache\n", 0},
		{"any-branch rules", "build:\n  rules:\n    - if: $CI_COMMIT_BRANCH\n  script:\n    - " + kaniko + " --cache\n", 1},
		{"template only", ".build:\n  script:\n    - " + kaniko + " --cache\n", 0},
		{"through extends", ".build:\n  script:\n    - " + kaniko + " --cache\nbuild:\n  extends: .build\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got int
			for _, f := range checkRule(t, GL046, tc.yaml) {
				if strings.Contains(f.Message, "registry build cache") {
					got++
				}
			}
			if got != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, got, checkRule(t, GL046, tc.yaml))
			}
		})
	}
}

func TestGL046_RegistryBuildCacheProtectedJobs(t *testing.T) {
	kaniko := "    - /kaniko/executor --destination app:1 --cache\n"
	for guard, want := range map[string]int{
		"  only: [tags]\n":                                           0,
		"  only: [main, tags]\n":                                     0,
		"  only: [branches]\n":                                       1,
		"  rules:\n    - if: $CI_COMMIT_TAG\n":                       0,
		"  rules:\n    - if: $CI_COMMIT_REF_PROTECTED == \"true\"\n": 0,
		"  rules:\n    - if: $CI_COMMIT_TAG\n    - when: manual\n":   1,
		"  rules:\n    - if: $CI_PIPELINE_SOURCE == \"push\"\n":      1,
	} {
		got := 0
		for _, f := range checkRule(t, GL046, "build:\n"+guard+"  script:\n"+kaniko) {
			if strings.Contains(f.Message, "registry build cache") {
				got++
			}
		}
		if got != want {
			t.Errorf("guard %q: expected %d, got %d", guard, want, got)
		}
	}
}
