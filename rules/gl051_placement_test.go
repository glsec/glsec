package rules

import "testing"

func TestGL051_DefaultHooksAndRunSteps(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    tool:
      description: free text
---
default:
  services:
    - $[[ inputs.tool ]]
  before_script:
    - install $[[ inputs.tool ]]
  hooks:
    pre_get_sources_script:
      - fetch $[[ inputs.tool ]]
build:
  run:
    - name: one
      script: run $[[ inputs.tool ]]
    - name: remote
      step: gitlab.com/some/step@v1
  hooks:
    pre_get_sources_script:
      - prep $[[ inputs.tool ]]
`)
	lines := map[int]bool{}
	for _, x := range f {
		lines[x.Line] = true
	}
	for _, want := range []int{9, 11, 14, 18, 23} {
		if !lines[want] {
			t.Errorf("expected a GL051 finding on line %d, got %+v", want, f)
		}
	}
}

func TestGL001_DefaultImageAndServices(t *testing.T) {
	f := findings(t, `
default:
  image: node:latest
  services:
    - postgres:latest
    - name: redis
job:
  script: [echo]
`)
	lines := map[int]bool{}
	for _, x := range f {
		lines[x.Line] = true
	}
	for _, want := range []int{3, 5} {
		if !lines[want] {
			t.Errorf("expected a GL001 finding on line %d, got %+v", want, f)
		}
	}
}

func TestGL001_TopLevelVariableResolution(t *testing.T) {
	f := findings(t, `
variables:
  BASE: node:latest
job:
  image: $BASE
  script: [echo]
`)
	if len(f) != 1 || f[0].Line != 5 {
		t.Fatalf("an image variable set to :latest at top level should be flagged on line 5, got %+v", f)
	}
}
