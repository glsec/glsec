// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
)

// A job in a file with include: that has no script:, trigger: or run: of its
// own can only be an override of an included job, which may carry the
// missing keys (#978).
func TestIncludedJobOverrides(t *testing.T) {
	const include = "include:\n  - project: example/ci-templates\n    ref: 0123456789abcdef0123456789abcdef01234567\n    file: /ci.yml\n"
	for _, tc := range []struct {
		rule rule.Rule
		job  string
	}{
		{GL013, "pages:\n  needs: [docs]\n"},
		{GL080, "release-job:\n  dependencies: []\n"},
		{GL081, "cloud-job:\n  id_tokens:\n    CLOUD_TOKEN:\n      aud: https://example.com\n"},
		{GL005, "build:\n  artifacts:\n    paths: [dist/]\n"},
		{GL017, "deploy:\n  environment: production\n"},
		{GL019, "deploy:\n  environment: production\n"},
	} {
		t.Run(tc.rule.ID(), func(t *testing.T) {
			check := func(src string) int {
				doc, err := parser.Parse([]byte(src), "test.yml")
				if err != nil {
					t.Fatal(err)
				}
				n := 0
				for _, f := range Check(tc.rule, doc, "test.yml") {
					if f.Job != "" {
						n++
					}
				}
				return n
			}
			if n := check(include + tc.job); n != 0 {
				t.Errorf("override in a file with include: got %d findings, want 0", n)
			}
			// The same job with a script: is a whole job and still checked.
			if n := check(include + tc.job + "  script: [./run.sh]\n"); n == 0 {
				t.Error("a job with its own script: is no longer checked")
			}
		})
	}
}
