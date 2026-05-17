package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings016(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	r := &gl016{}
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return r.Check(doc.Root, "test.yml")
}

func findings016trusted(t *testing.T, yaml string, trusted []string) []finding.Finding {
	t.Helper()
	r := &gl016{trustedHosts: trusted}
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return r.Check(doc.Root, "test.yml")
}

func TestGL016_IncludeRemoteHTTP_Error(t *testing.T) {
	f := findings016(t, `
include:
  - remote: "http://templates.example.com/ci.yml"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity for include:remote, got %s", f[0].Severity)
	}
}

func TestGL016_IncludeRemoteHTTPS_NoFinding(t *testing.T) {
	f := findings016(t, `
include:
  - remote: "https://templates.example.com/ci.yml"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for HTTPS include, got %d", len(f))
	}
}

func TestGL016_IncludeRemoteLocalhost_NoFinding(t *testing.T) {
	f := findings016(t, `
include:
  - remote: "http://localhost/ci.yml"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for localhost, got %d", len(f))
	}
}

func TestGL016_IncludeRemotePrivateIP_Info(t *testing.T) {
	f := findings016(t, `
include:
  - remote: "http://10.0.1.5/ci.yml"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for private IP, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info severity for private IP, got %s", f[0].Severity)
	}
}

func TestGL016_IncludeRemoteInternalTLD_Info(t *testing.T) {
	f := findings016(t, `
include:
  - remote: "http://templates.internal/ci.yml"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .internal host, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info severity for .internal TLD, got %s", f[0].Severity)
	}
}

func TestGL016_ScriptCurlHTTP_Warn(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - curl http://install.example.com/tool.sh -o tool.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for curl http://, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity for script curl, got %s", f[0].Severity)
	}
}

func TestGL016_ScriptWgetHTTP_Warn(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - wget http://install.example.com/tool.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for wget http://, got %d", len(f))
	}
}

func TestGL016_ScriptCurlHTTPS_NoFinding(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - curl https://install.example.com/tool.sh -o tool.sh
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for curl https://, got %d", len(f))
	}
}

func TestGL016_ScriptCurlLocalhost_NoFinding(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - curl http://localhost:8080/health
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for localhost, got %d", len(f))
	}
}

func TestGL016_ScriptCurlPrivate_Info(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - curl http://192.168.1.10/artifact.tar.gz -o artifact.tar.gz
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for private IP in script, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info for private IP, got %s", f[0].Severity)
	}
}

func TestGL016_VariableHTTP_Warn(t *testing.T) {
	f := findings016(t, `
variables:
  REGISTRY: "http://registry.example.com"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for variable with http://, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn for public host in variable, got %s", f[0].Severity)
	}
}

func TestGL016_VariableHTTPInternal_Info(t *testing.T) {
	f := findings016(t, `
variables:
  NEXUS: "http://nexus.internal/repo"
build:
  script: [echo ok]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .internal variable, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info for .internal variable, got %s", f[0].Severity)
	}
}

func TestGL016_TrustedHost_NoFinding(t *testing.T) {
	f := findings016trusted(t, `
variables:
  NEXUS: "http://nexus.corp.example.com/repo"
build:
  script:
    - curl http://nexus.corp.example.com/tool.sh -o tool.sh
`, []string{"nexus.corp.example.com"})
	if len(f) != 0 {
		t.Errorf("expected no finding for trusted host, got %d", len(f))
	}
}

func TestGL016_TrustedCIDR_NoFinding(t *testing.T) {
	f := findings016trusted(t, `
build:
  script:
    - curl http://10.5.2.3/artifact.tar.gz -o artifact.tar.gz
`, []string{"10.0.0.0/8"})
	if len(f) != 0 {
		t.Errorf("expected no finding for host in trusted CIDR, got %d", len(f))
	}
}

func TestGL016_TopLevelBeforeScript_Warn(t *testing.T) {
	f := findings016(t, `
before_script:
  - curl http://install.example.com/setup.sh -o setup.sh

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for top-level before_script curl http://, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL016_TopLevelAfterScript_Warn(t *testing.T) {
	f := findings016(t, `
after_script:
  - wget http://metrics.example.com/report

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for top-level after_script wget http://, got %d", len(f))
	}
}

func TestGL016_DefaultVariables_Warn(t *testing.T) {
	f := findings016(t, `
default:
  variables:
    REGISTRY: "http://registry.example.com"

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for default: variables: http://, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity for public host in default variable, got %s", f[0].Severity)
	}
}

func TestGL016_DefaultBeforeScript_Warn(t *testing.T) {
	f := findings016(t, `
default:
  before_script:
    - curl http://nexus.example.com/tool.sh -o tool.sh

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for default: before_script curl http://, got %d", len(f))
	}
}

func TestGL016_DefaultVariablesInternal_Info(t *testing.T) {
	f := findings016(t, `
default:
  variables:
    NEXUS: "http://nexus.internal/repo"

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for default: variables: internal http://, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info severity for internal host, got %s", f[0].Severity)
	}
}

func TestGL016_LineNumber(t *testing.T) {
	f := findings016(t, `
include:
  - remote: "http://templates.example.com/ci.yml"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}
