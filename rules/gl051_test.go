package rules

import (
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
	return GL051.Check(doc.Root, "test.yml")
}

func TestGL051_UnconstrainedInputInImage(t *testing.T) {
	f := findings051(t, `
spec:
  inputs:
    deploy_image:
      description: "Image to use"

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

build:
  image: $[[inputs.img]]
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for compact interpolation syntax, got %d", len(f))
	}
}
