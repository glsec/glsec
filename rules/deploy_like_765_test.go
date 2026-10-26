// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestDeployLikeName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"deploy-production", true},
		{"build_and_push", true},
		{"build and publish tag", true},
		{"release_docker_latest", true},
		{"release-build", false},
		{"assemblerelease", false},
		{"build-migrationsfile", false},
		{"check migrations", false},
		{"release/gitleaks-scan", false},
		{"deployment test", false},
		{"postdeploy_test", false},
		{"lint", false},
	} {
		if got := deployLikeName(tc.name, deployLikeKeywords); got != tc.want {
			t.Errorf("deployLikeName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestEdgeCases765(t *testing.T) {
	for _, tc := range []struct {
		name, rule, yaml string
		want             int
	}{
		{"GL005 sensitive pattern under exclude", "GL005", "j:\n  artifacts:\n    expire_in: 1 day\n    paths: [k8s/]\n    exclude:\n      - ./k8s/**/*-secret.yaml\n  script: [x]\n", 0},
		{"GL005 sensitive pattern under paths", "GL005", "j:\n  artifacts:\n    expire_in: 1 day\n    paths: [.env]\n  script: [x]\n", 1},
		{"GL043 \\A \\z", "GL043", "j:\n  rules:\n    - if: '$CI_COMMIT_REF_NAME =~ /\\A[0-9]+-[0-9]+-stable\\z/'\n  script: [x]\n", 0},
		{"GL043 trailing .*", "GL043", "j:\n  rules:\n    - if: '$CI_COMMIT_BRANCH =~ /^release\\/.*/'\n  script: [x]\n", 0},
		{"GL043 prefix only", "GL043", "j:\n  rules:\n    - if: '$CI_COMMIT_BRANCH =~ /^release/'\n  script: [x]\n", 1},
		{"GL053 Workflows template", "GL053", "include:\n  - template: Workflows/MergeRequest-Pipelines.gitlab-ci.yml\nj:\n  script: [x]\n", 0},
		{"GL053 only when never", "GL053", "workflow:\n  rules:\n    - when: never\nj:\n  script: [x]\n", 0},
		{"GL053 no workflow", "GL053", "j:\n  script: [x]\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tc.yaml), "t.yml")
			if err != nil {
				t.Fatal(err)
			}
			var n int
			switch tc.rule {
			case "GL005":
				n = len(GL005.Check(doc.Root, "t.yml"))
			case "GL043":
				n = len(GL043.Check(doc.Root, "t.yml"))
			case "GL053":
				n = len(GL053.Check(doc.Root, "t.yml"))
			}
			if n != tc.want {
				t.Fatalf("expected %d findings, got %d", tc.want, n)
			}
		})
	}
}
