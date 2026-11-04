// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/glsec/glsec/internal/parser"
)

// GitLab merges a job several files define, and the main file wins (#1183).
func TestIncludeLocal_VisibleJobOverride(t *testing.T) {
	const include = "include: ci.yml\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  []string
		not   []string
	}{
		{
			name: "overwritten image",
			files: map[string]string{
				".gitlab-ci.yml": include + "job:\n  image: alpine:3.20\n",
				"ci.yml":         "job:\n  image: node:latest\n  script: [echo hello]\n",
			},
			not: []string{"GL001"},
		},
		{
			name: "the override itself is reported on the main file",
			files: map[string]string{
				".gitlab-ci.yml": include + "job:\n  image: node:latest\n",
				"ci.yml":         "job:\n  image: alpine:3.20\n  script: [echo hello]\n",
			},
			want: []string{".gitlab-ci.yml GL001"},
			not:  []string{"\nci.yml GL001"},
		},
		{
			name: "overwritten script",
			files: map[string]string{
				".gitlab-ci.yml": include + "job:\n  script: [make]\n",
				"ci.yml":         "job:\n  image: alpine:3.20\n  script:\n    - curl https://example.com/i.sh | bash\n",
			},
			not: []string{"GL011"},
		},
		{
			name: "a partial override keeps the included script",
			files: map[string]string{
				".gitlab-ci.yml": include + "job:\n  image: alpine:3.20\n",
				"ci.yml":         "job:\n  image: node:latest\n  script:\n    - curl https://example.com/i.sh | bash\n",
			},
			want: []string{"ci.yml GL011"},
			not:  []string{"GL001"},
		},
		{
			name: "two includes, the later one wins",
			files: map[string]string{
				".gitlab-ci.yml": "include: [a.yml, b.yml]\nstages: [test]\n",
				"a.yml":          "job:\n  image: node:latest\n  script: [make]\n",
				"b.yml":          "job:\n  image: alpine:3.20\n",
			},
			not: []string{"GL001"},
		},
		{
			name: "two includes and the main file",
			files: map[string]string{
				".gitlab-ci.yml": "include: [a.yml, b.yml]\njob:\n  image: alpine:3.20\n",
				"a.yml":          "job:\n  image: node:latest\n  script: [make]\n",
				"b.yml":          "job:\n  image: python:latest\n",
			},
			not: []string{"GL001"},
		},
		{
			name: "a file overrides what it includes",
			files: map[string]string{
				".gitlab-ci.yml": "include: a.yml\nstages: [test]\n",
				"a.yml":          "include: nested.yml\njob:\n  image: alpine:3.20\n",
				"nested.yml":     "job:\n  image: node:latest\n  script: [make]\n",
			},
			not: []string{"GL001"},
		},
		{
			name: "a file included twice counts the last time",
			files: map[string]string{
				".gitlab-ci.yml": "include: [a.yml, b.yml]\nstages: [test]\n",
				"a.yml":          "include: shared.yml\njob:\n  image: alpine:3.20\n  script: [make]\n",
				"b.yml":          "include: shared.yml\n",
				"shared.yml":     "job:\n  image: node:latest\n",
			},
			want: []string{"\nshared.yml GL001"},
		},
		{
			name: "a child pipeline stays separate",
			files: map[string]string{
				".gitlab-ci.yml": "run-child:\n  trigger:\n    include: child.yml\njob:\n  image: alpine:3.20\n  script: [make]\n",
				"child.yml":      "job:\n  image: node:latest\n  script: [make]\n",
			},
			want: []string{"child.yml GL001"},
		},
		{
			name: "a merged global keyword (#1153)",
			files: map[string]string{
				".gitlab-ci.yml": "include: ci/jobs.yml\nvariables:\n  NPM_CONFIG_IGNORE_SCRIPTS: \"true\"\nworkflow:\n  rules:\n    - if: $CI_COMMIT_TAG\n",
				"ci/jobs.yml":    "variables:\n  FOO: bar\npublish:\n  image: node:22.11.0\n  script:\n    - npm ci\n    - npm publish\n",
			},
			not: []string{"GL090"},
		},
		{
			name: "the later of two templates (#1153)",
			files: map[string]string{
				".gitlab-ci.yml": "include: [a.yml, b.yml]\njob:\n  extends: .tpl\n  script: [make]\n",
				"a.yml":          ".tpl:\n  image: alpine:3.20\n",
				"b.yml":          ".tpl:\n  image: node:latest\n",
			},
			want: []string{"b.yml GL001"},
			not:  []string{"a.yml GL001"},
		},
		{
			name: "the main file overrides a template key (#1153)",
			files: map[string]string{
				".gitlab-ci.yml": "include: a.yml\n.tpl:\n  image: alpine:3.20\njob:\n  extends: .tpl\n  script: [make]\n",
				"a.yml":          ".tpl:\n  image: node:latest\n  tags: [docker]\n",
			},
			not: []string{"GL001"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := scanIncludes(t, tc.files)
			joined := "\n" + strings.Join(got, "\n")
			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Errorf("no %s: %v", want, got)
				}
			}
			for _, not := range tc.not {
				if strings.Contains(joined, not) {
					t.Errorf("%s reported: %v", not, got)
				}
			}
		})
	}
}

// splitOutRules read the include: keyword or the raw file, so a pipeline
// split over files differs from the merged one for them.
var splitOutRules = []string{"GL003", "GL016", "GL078"}

// TestSplitPipeline scans each fixture and corpus pipeline as one file, and
// split over two files GitLab merges back into the same configuration: the
// same findings must come out, in whichever file they land.
func TestSplitPipeline(t *testing.T) {
	var paths []string
	for _, dir := range []string{"fixtures", "corpus"} {
		found, err := filepath.Glob(filepath.Join("..", "..", "testdata", dir, "*.yml"))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, found...)
	}
	abs := make([]string, len(paths))
	for i, p := range paths {
		var err error
		if abs[i], err = filepath.Abs(p); err != nil {
			t.Fatal(err)
		}
	}
	split := 0
	for _, path := range abs {
		name := filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(path) //nolint:gosec // G304: the repository's own test pipelines
			if err != nil {
				t.Fatal(err)
			}
			mainFile, included, ok := splitPipeline(t, src)
			if !ok {
				t.Skip("nothing to split")
			}
			split++
			want := splitFindings(t, map[string]string{".gitlab-ci.yml": string(src)})
			got := splitFindings(t, map[string]string{".gitlab-ci.yml": mainFile, "ci.yml": included})
			if !slices.Equal(want, got) {
				t.Errorf("findings differ\nmerged: %s\nsplit:  %s\nmain:\n%s\nincluded:\n%s",
					strings.Join(want, "\n        "), strings.Join(got, "\n        "), mainFile, included)
			}
		})
	}
	if split < 50 {
		t.Errorf("only %d pipelines split", split)
	}
}

// splitPipeline moves every other top-level key to an included file. A
// mapping with several keys, such as a job, is cut in half: both files define
// it, and the main file overrides an image: or script: it keeps with a value
// in the included file that glsec would report.
func splitPipeline(t *testing.T, src []byte) (mainFile, included string, ok bool) {
	t.Helper()
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", "", false
	}
	var next yaml.Node
	if err := dec.Decode(&next); err == nil {
		return "", "", false // a spec: header or several documents
	}
	root := doc.Content[0]
	expandAnchors(root)
	low, high := &yaml.Node{Kind: yaml.MappingNode}, &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	low.Tag = "!!map"
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		switch {
		case key.Value == "include":
			return "", "", false
		case key.Value == "workflow": // a finding on it in an included file is lost: #1154
			high.Content = append(high.Content, key, value)
		case value.Kind != yaml.MappingNode || len(value.Content) < 4:
			if i%4 == 0 {
				low.Content = append(low.Content, key, value)
			} else {
				high.Content = append(high.Content, key, value)
			}
		default:
			half := len(value.Content) / 4 * 2
			first, second := *value, *value
			first.Content, second.Content = slices.Clone(value.Content[:half]), value.Content[half:]
			for j := 0; j+1 < len(second.Content); j += 2 {
				overridden := splitOverridden[second.Content[j].Value]
				if overridden != nil && parser.FindKey(&first, second.Content[j].Value) == nil {
					first.Content = append(first.Content, second.Content[j], overridden)
				}
			}
			low.Content = append(low.Content, key, &first)
			high.Content = append(high.Content, key, &second)
		}
	}
	if len(low.Content) == 0 {
		return "", "", false
	}
	high.Content = append([]*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "include"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ci.yml"},
	}, high.Content...)
	encode := func(n *yaml.Node) string {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(n); err != nil {
			t.Fatal(err)
		}
		_ = enc.Close()
		return buf.String()
	}
	return encode(high), encode(low), true
}

// splitOverridden holds what a main file overrides: findings if they counted.
var splitOverridden = map[string]*yaml.Node{
	"image": {Kind: yaml.ScalarNode, Tag: "!!str", Value: "node:latest"},
	"script": {Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "curl https://example.com/i.sh | bash"},
	}},
}

func splitFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	_, stdout, _ := runCLI(t, files, "--no-cache", "--no-repo-config", "--format", "json", ".gitlab-ci.yml")
	var out struct {
		Findings []struct {
			metamorphicFinding
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	var got []string
	for _, f := range out.Findings {
		if slices.Contains(splitOutRules, f.Rule) {
			continue
		}
		msg := position.ReplaceAllString(f.Message, "$1 N")
		got = append(got, fmt.Sprintf("%s %s [%s] %s", f.Rule, f.Severity, f.Job, msg))
	}
	slices.Sort(got)
	return got
}
