package parser

import (
	"reflect"
	"sort"
	"testing"
)

func TestChildPipelinePaths(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "no trigger",
			yaml: "build:\n  script:\n    - make\n",
			want: nil,
		},
		{
			name: "multi-project trigger (no include)",
			yaml: "deploy:\n  trigger:\n    project: my-group/my-project\n    branch: main\n",
			want: nil,
		},
		{
			name: "scalar include shorthand",
			yaml: "child:\n  trigger:\n    include: .gitlab/child.yml\n",
			want: []string{".gitlab/child.yml"},
		},
		{
			name: "sequence with local key",
			yaml: "child:\n  trigger:\n    include:\n      - local: .gitlab/a.yml\n      - local: .gitlab/b.yml\n",
			want: []string{".gitlab/a.yml", ".gitlab/b.yml"},
		},
		{
			name: "sequence with mixed types (ignores non-local)",
			yaml: "child:\n  trigger:\n    include:\n      - local: ci/child.yml\n      - remote: https://example.com/ci.yml\n",
			want: []string{"ci/child.yml"},
		},
		{
			name: "multiple jobs each with a child",
			yaml: "job-a:\n  trigger:\n    include: a.yml\njob-b:\n  trigger:\n    include: b.yml\n",
			want: []string{"a.yml", "b.yml"},
		},
		{
			name: "trigger with string value (not mapping)",
			yaml: "job:\n  trigger: my-group/my-project\n",
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := Parse([]byte(tc.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			got := ChildPipelinePaths(doc.Root)
			sort.Strings(got)
			want := tc.want
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %v, want %v", got, want)
			}
		})
	}
}
