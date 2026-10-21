// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings051(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return Check(GL051, doc, "test.yml")
}

func TestGL051_UnconstrainedInputInImage(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    deploy_image:
      description: "Image to use"
---
deploy:
  image: $[[ inputs.deploy_image ]]
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
	if f[0].Job != "deploy" {
		t.Errorf("expected job 'deploy', got %q", f[0].Job)
	}
}

func TestGL051_ConstrainedByOptions_NoFinding(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    environment:
      options:
        - staging
        - production
---
deploy:
  image: alpine:3.19
  script:
    - echo $[[ inputs.environment ]]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for options-constrained input, got %d", len(f))
	}
}

func TestGL051_ConstrainedByRegex_NoFinding(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    image_tag:
      regex: '^[a-zA-Z0-9._-]+$'
---
deploy:
  image: alpine:$[[ inputs.image_tag ]]
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for regex-constrained input, got %d", len(f))
	}
}

func TestGL051_UnconstrainedInputInScript(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    command:
      description: "Command to run"
---
run:
  script:
    - $[[ inputs.command ]]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for script injection, got %d", len(f))
	}
}

func TestGL051_UnconstrainedInputInBeforeScript(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    setup_cmd:
---
run:
  before_script:
    - $[[ inputs.setup_cmd ]]
  script:
    - ./build.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for before_script injection, got %d", len(f))
	}
}

func TestGL051_UnconstrainedInputInAfterScript(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    cleanup_cmd:
---
run:
  script:
    - ./build.sh
  after_script:
    - $[[ inputs.cleanup_cmd ]]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for after_script injection, got %d", len(f))
	}
}

func TestGL051_UnconstrainedInputInEnvironmentName(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    deploy_env:
      description: "Target environment"
---
deploy:
  script:
    - ./deploy.sh
  environment:
    name: $[[ inputs.deploy_env ]]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for environment:name: injection, got %d", len(f))
	}
}

func TestGL051_UnconstrainedInputInEnvironmentScalar(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    deploy_env:
---
deploy:
  script:
    - ./deploy.sh
  environment: $[[ inputs.deploy_env ]]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for environment scalar injection, got %d", len(f))
	}
}

func TestGL051_UnconstrainedInputInServices(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    svc_image:
---
test:
  services:
    - $[[ inputs.svc_image ]]
  script:
    - ./test.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for services: injection, got %d", len(f))
	}
}

func TestGL051_NoSpecInputs_NoFinding(t *testing.T) {
	f := findings051(t, `
deploy:
  image: alpine:3.19
  script:
    - ./deploy.sh
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without spec:inputs, got %d", len(f))
	}
}

func TestGL051_ImageMappingForm(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    runner_image:
---
build:
  image:
    name: $[[ inputs.runner_image ]]
    entrypoint: [""]
  script:
    - make build
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for image mapping form, got %d", len(f))
	}
}

func TestGL051_MultipleUnconstrainedInputs(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    image_name:
    run_cmd:
---
job:
  image: $[[ inputs.image_name ]]
  script:
    - $[[ inputs.run_cmd ]]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for two unconstrained inputs, got %d", len(f))
	}
}

func TestGL051_ConstrainedInputNotUsedInSensitiveKey_NoFinding(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    version:
      regex: '^\d+\.\d+\.\d+$'
    env:
      options:
        - staging
        - production
---
deploy:
  image: myapp:$[[ inputs.version ]]
  script:
    - echo "Deploying to $[[ inputs.env ]]"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for fully constrained inputs, got %d", len(f))
	}
}

func TestGL051_InputWithDefaultButNoConstraint(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    deploy_image:
      default: "alpine:3.19"
---
deploy:
  image: $[[ inputs.deploy_image ]]
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for input with only default (no regex/options), got %d", len(f))
	}
}

func TestGL051_WhitespaceVariantsInInterpolation(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    img:
---
build:
  image: $[[inputs.img]]
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for compact interpolation syntax, got %d", len(f))
	}
}

func TestGL051_SingleDocumentForm(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    img:
deploy:
  image: $[[ inputs.img ]]
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding when spec: shares the document with the jobs, got %d", len(f))
	}
}

func TestGL051_TypedInputs_NoFinding(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    count:
      type: number
      default: 1
    debug:
      type: boolean
      default: false
---
job:
  script:
    - ./run.sh $[[ inputs.count ]] $[[ inputs.debug ]]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for number/boolean inputs, got %d", len(f))
	}
}

func TestGL051_RulesWithOptions_NoFinding(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    cloud:
      options: [aws, gcp]
    size:
      rules:
        - if: $[[ inputs.cloud ]] == 'aws'
          options: [t3.micro, t3.small]
        - options: [small, large]
---
job:
  script:
    - ./provision.sh $[[ inputs.size ]]
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when every rules entry has options, got %d", len(f))
	}
}

func TestGL051_RulesWithFreeTextEntry(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    kind:
      options: [standard, custom]
    config:
      rules:
        - if: $[[ inputs.kind ]] == 'custom'
          default: null
---
job:
  script:
    - ./configure.sh $[[ inputs.config ]]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a rules entry without options, got %d", len(f))
	}
}

func TestGL051_ArrayInput(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    servers:
      type: array
    tags:
      type: array
      options: [docker, linux]
---
job:
  script:
    - curl "https://$[[ inputs.servers[0].host ]]:$[[ inputs.servers[0].port ]]"
    - echo $[[ inputs.tags[0] ]]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for the unconstrained indexed array input, got %d", len(f))
	}
}

func TestGL051_PipedFunctions(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    a:
    b:
---
job:
  script:
    - echo $[[ inputs.a | expand_vars | truncate(5,8) ]]
    - printf '%s\n' $[[ inputs.b | posix_escape ]]
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for piped interpolations, got %d", len(f))
	}
	for _, x := range f {
		hasNote := strings.Contains(x.Message, "posix_escape is not a security control")
		if hasNote != strings.Contains(x.Message, `"b"`) {
			t.Errorf("posix_escape note on the wrong finding: %s", x.Message)
		}
	}
}

func TestGL051_NamePrefixDoesNotMatch(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    img:
    img2:
      options: [a, b]
---
job:
  script:
    - echo $[[ inputs.img2 ]]
`)
	if len(f) != 0 {
		t.Fatalf("an unconstrained input must not match a longer input name, got %d", len(f))
	}
}

func TestGL051_JobInputs(t *testing.T) {
	f := findings051(t, `
deploy:
  when: manual
  inputs:
    version:
      default: latest
    target_env:
      default: staging
      options: [staging, production]
    replicas:
      type: number
      default: 3
    migration:
      default: ""
      regex: ^[a-zA-Z0-9_]*$
    img:
      default: alpine:3.24
  image: ${{ job.inputs.img }}
  script:
    - ./deploy.sh --env ${{ job.inputs.target_env }} --version ${{ job.inputs.version }}
    - ./scale.sh ${{ job.inputs.replicas }}
    - ./migrate.sh '${{ job.inputs.migration }}'
  artifacts:
    paths:
      - reports/${{ job.inputs.version }}/
`)
	want := map[string]int{"version": 2, "img": 1}
	got := map[string]int{}
	for _, x := range f {
		if x.Severity != finding.Error {
			t.Errorf("deploy job: expected error, got %s (%s)", x.Severity, x.Message)
		}
		for name := range want {
			if strings.Contains(x.Message, `job input "`+name+`"`) {
				got[name]++
			}
		}
	}
	if len(f) != 3 || got["version"] != 2 || got["img"] != 1 {
		t.Errorf("expected version in script and artifacts plus img in image, got %+v", f)
	}
}

func TestGL051_JobInputsWarnOutsideDeploy(t *testing.T) {
	f := findings051(t, `
test:
  inputs:
    suite:
      default: smoke
  script:
    - 'make test SUITE=${{ job.inputs.suite | upper }}'
`)
	if len(f) != 1 || f[0].Severity != finding.Warn {
		t.Fatalf("expected one warning for an expression using the input, got %+v", f)
	}
}

func TestGL051_JobInputNamePrefix(t *testing.T) {
	f := findings051(t, `
test:
  inputs:
    tag:
      default: x
    tags:
      default: [a]
      type: array
      options: [a, b]
  script:
    - 'echo ${{ job.inputs.tags }}'
`)
	if len(f) != 0 {
		t.Fatalf("an unconstrained input must not match a longer input name, got %+v", f)
	}
}
