// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
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

func TestGL016_ScriptGitCloneHTTP_Warn(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - git clone http://git.example.com/vendor/lib.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for git clone http://, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity for git clone over HTTP, got %s", f[0].Severity)
	}
}

func TestGL016_ScriptGitSubcommandsHTTP_Warn(t *testing.T) {
	for _, line := range []string{
		"git -C vendor clone --depth 1 http://git.example.com/lib.git",
		"git fetch http://git.example.com/lib.git main",
		"git pull http://git.example.com/lib.git",
		"git remote add upstream http://git.example.com/lib.git",
		"git submodule add http://git.example.com/lib.git vendor/lib",
	} {
		f := findings016(t, "build:\n  script:\n    - "+line+"\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %q, got %d", line, len(f))
		}
	}
}

func TestGL016_ScriptGitCloneHTTPS_NoFinding(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - git clone https://git.example.com/vendor/lib.git
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for git clone https://, got %d", len(f))
	}
}

func TestGL016_ScriptGitProtocol_Warn(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - git clone git://git.example.com/vendor/lib.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for git:// clone, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity for git:// transport, got %s", f[0].Severity)
	}
}

func TestGL016_ScriptGitProtocolPrivate_Info(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - git clone git://10.0.1.5/vendor/lib.git
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for git:// to private IP, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info severity for private host, got %s", f[0].Severity)
	}
}

func TestGL016_ScriptGitProtocolTrusted_NoFinding(t *testing.T) {
	f := findings016trusted(t, `
build:
  script:
    - git clone git://git.corp.example.com/vendor/lib.git
`, []string{"git.corp.example.com"})
	if len(f) != 0 {
		t.Errorf("expected no finding for trusted host, got %d", len(f))
	}
}

func TestGL016_VariableGitProtocol_Warn(t *testing.T) {
	f := findings016(t, `
variables:
  VENDOR_REPO: "git://git.example.com/vendor/lib.git"
build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for git:// variable, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn for public host in git:// variable, got %s", f[0].Severity)
	}
}

func TestGL016_VariableGitProtocolInternal_Info(t *testing.T) {
	f := findings016(t, `
variables:
  VENDOR_REPO: "git://git.internal/vendor/lib.git"
build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for internal git:// variable, got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info for .internal host, got %s", f[0].Severity)
	}
}

func TestGL016_IncludeRemoteGitProtocol_Error(t *testing.T) {
	f := findings016(t, `
include:
  - remote: "git://templates.example.com/ci.yml"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for git:// include, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity for git:// include, got %s", f[0].Severity)
	}
}

// The scheme match is anchored on a word boundary so substrings such as
// "digit://" in an unrelated URL path do not count as git transport.
func TestGL016_GitSchemeSubstring_NoFinding(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - echo "see https://docs.example.com/digit://notes"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for digit:// substring, got %d", len(f))
	}
}

func TestGL016_ScriptGitStatusNoURL_NoFinding(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - git status
    - git log --oneline -1
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for plain git commands, got %d", len(f))
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

// curl and wget treat the URL scheme case-insensitively (RFC 3986), so
// HTTP:// and Http:// still download over plain HTTP (#827).
func TestGL016_ScriptUppercaseScheme_Warn(t *testing.T) {
	for _, line := range []string{
		"curl -fsSL HTTP://example.com/tool -o tool",
		"wget Http://example.com/tool",
	} {
		f := findings016(t, "build:\n  script:\n    - "+line+"\n")
		if len(f) != 1 {
			t.Errorf("%q: expected 1 finding, got %d", line, len(f))
			continue
		}
		if f[0].Severity != finding.Warn {
			t.Errorf("%q: expected Warn severity, got %s", line, f[0].Severity)
		}
	}
}

// The host checks still apply with an uppercase scheme: loopback and trusted
// hosts are skipped, and a private host is only Info.
func TestGL016_ScriptUppercaseSchemeHosts(t *testing.T) {
	f := findings016trusted(t, `
build:
  script:
    - curl HTTP://localhost:8080/health
    - curl HTTP://mirror.example.com/tool -o tool
    - curl HTTP://10.0.0.5/tool -o tool
`, []string{"mirror.example.com"})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (the private host), got %d", len(f))
	}
	if f[0].Severity != finding.Info {
		t.Errorf("expected Info severity for a private host, got %s", f[0].Severity)
	}
}

func TestGL016_ScriptUppercaseHTTPS_NoFinding(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - curl -fsSL HTTPS://example.com/tool -o tool
    - wget Https://example.com/tool
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for HTTPS://, got %d", len(f))
	}
}

// git, unlike curl and wget, refuses an uppercase scheme ("git:
// 'remote-HTTP' is not a git command"), so nothing is fetched over HTTP.
func TestGL016_GitUppercaseScheme_NoFinding(t *testing.T) {
	f := findings016(t, `
build:
  script:
    - git clone HTTP://git.example.com/vendor/lib.git
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for git clone HTTP://, got %d", len(f))
	}
}

// A probe that throws the response away fetches nothing to trust (#1279).
func TestGL016_Probes(t *testing.T) {
	for line, want := range map[string]int{
		`timeout 60s sh -c 'until curl -sf http://example.com/health > /dev/null; do sleep 1; done'`: 0,
		`wget --spider http://example.com/`:                         0,
		`wget -q -O /dev/null http://example.com/`:                  0,
		`curl -s -o /dev/null http://example.com/`:                  0,
		`curl -s -w '%{http_code}' http://example.com/`:             1,
		`curl -s -o resp.txt -w '%{http_code}' http://example.com/`: 1,
		`curl -I http://example.com/`:                               0,
		`curl -fsS http://example.com/health 1>/dev/null`:           0,
		`curl -s http://example.com/health 2>/dev/null`:             1,
		`curl -s http://example.com/install.sh > /dev/null | sh`:    1,
		`curl -s http://example.com/install.sh | sh > /dev/null`:    1,
		`curl -sO http://example.com/tool.tar.gz > /dev/null`:       1,
		`curl -o tool.tgz http://example.com/tool.tgz > /dev/null`:  1,
		`wget http://example.com/tool.tgz > /dev/null`:              1,
		`curl -s http://example.com/`:                               1,
	} {
		t.Run(line, func(t *testing.T) {
			if f := findings016(t, fmt.Sprintf("job:\n  script:\n    - %q\n", line)); len(f) != want {
				t.Fatalf("got %v, want %d findings", f, want)
			}
		})
	}
}

func TestGL016_ProbeOptionClusters(t *testing.T) {
	for line, want := range map[string]int{
		`curl -so /dev/null http://example.com/`:      0,
		`curl -sSo tool.tgz http://example.com/x.tgz`: 1,
	} {
		if f := findings016(t, fmt.Sprintf("job:\n  script:\n    - %q\n", line)); len(f) != want {
			t.Errorf("%s: got %v, want %d findings", line, f, want)
		}
	}
}
