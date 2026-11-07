// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func TestGL042(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "curl -k",
			yaml: `build:
  script:
    - curl -k https://internal.example.com/artifact.tar.gz`,
			wantHits: 1,
		},
		{
			name: "curl --insecure",
			yaml: `build:
  script:
    - curl --insecure https://internal.example.com/artifact.tar.gz`,
			wantHits: 1,
		},
		{
			name: "wget --no-check-certificate",
			yaml: `build:
  script:
    - wget --no-check-certificate https://internal.example.com/file.zip`,
			wantHits: 1,
		},
		{
			name: "git with http.sslVerify=false",
			yaml: `build:
  script:
    - git -c http.sslVerify=false clone https://gitlab.example.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "npm --strict-ssl=false",
			yaml: `build:
  script:
    - npm install --strict-ssl=false`,
			wantHits: 1,
		},
		{
			name: "npm config set strict-ssl false",
			yaml: `build:
  script:
    - npm config set strict-ssl false
    - npm install`,
			wantHits: 1,
		},
		{
			name: "GIT_SSL_NO_VERIFY inline in script",
			yaml: `build:
  script:
    - GIT_SSL_NO_VERIFY=true git clone https://gitlab.example.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "GIT_SSL_NO_VERIFY in variables block",
			yaml: `variables:
  GIT_SSL_NO_VERIFY: "true"

build:
  script:
    - git clone https://gitlab.example.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "GIT_SSL_NO_VERIFY in job variables",
			yaml: `build:
  variables:
    GIT_SSL_NO_VERIFY: "1"
  script:
    - git clone https://gitlab.example.com/org/repo.git`,
			wantHits: 1,
		},
		{
			name: "pip --trusted-host",
			yaml: `build:
  script:
    - pip install --trusted-host pypi.org somepkg`,
			wantHits: 1,
		},
		{
			name: "pip3 --trusted-host",
			yaml: `build:
  script:
    - pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org somepkg`,
			wantHits: 1,
		},
		{
			name: "python -m pip --trusted-host",
			yaml: `build:
  script:
    - python -m pip install --trusted-host pypi.org somepkg`,
			wantHits: 1,
		},
		{
			name: "pip install without --trusted-host — safe",
			yaml: `build:
  script:
    - pip install somepkg`,
			wantHits: 0,
		},
		{
			name: "curl without -k — safe",
			yaml: `build:
  script:
    - curl https://example.com/file.tar.gz`,
			wantHits: 0,
		},
		{
			name: "curl with --cacert — safe",
			yaml: `build:
  script:
    - curl --cacert /etc/ssl/certs/internal-ca.crt https://internal.example.com/file`,
			wantHits: 0,
		},
		{
			name: "wget without --no-check-certificate — safe",
			yaml: `build:
  script:
    - wget https://example.com/file.zip`,
			wantHits: 0,
		},
		{
			name: "multiple violations",
			yaml: `build:
  script:
    - curl -k https://internal.example.com/a.tar.gz
    - wget --no-check-certificate https://internal.example.com/b.zip`,
			wantHits: 2,
		},
		{
			name: "before_script at top level",
			yaml: `before_script:
  - curl -k https://internal.example.com/setup.sh | bash`,
			wantHits: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL042.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}

// The message shows the value as written (#1005).
func TestGL042_GitSSLValueAsWritten(t *testing.T) {
	doc, err := parser.Parse([]byte("job:\n  variables:\n    GIT_SSL_NO_VERIFY: \"1\"\n  script:\n    - export GIT_SSL_NO_VERIFY=1 && git clone https://example.com/r.git\n"), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range GL042.Check(doc.Root, "t.yml") {
		if strings.Contains(f.Message, "true") {
			t.Errorf("message says true for the value 1: %s", f.Message)
		}
	}
}

func gl042Count(t *testing.T, src string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	return GL042.Check(doc.Root, "test.yml")
}

func TestGL042_ClusterAndRegistryTools(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{"kubectl get pods --insecure-skip-tls-verify", 1},
		{"kubectl --insecure-skip-tls-verify=true apply -f k8s/", 1},
		{"helm upgrade app ./chart --insecure-skip-tls-verify", 1},
		{"kubectl get pods --insecure-skip-tls-verify=false", 0},
		{"kubectl get pods", 0},
		{"podman push --tls-verify=false registry.example.com/app", 1},
		{"buildah push --tls-verify=false registry.example.com/app", 1},
		{"skopeo copy --src-tls-verify=false docker://a/b docker://c/d", 1},
		{"skopeo copy --dest-tls-verify=false docker://a/b docker://c/d", 1},
		{"podman push --tls-verify=true registry.example.com/app", 0},
		{"docker push registry.example.com/app --tls-verify=false", 0},
		{"dockerd --insecure-registry=registry.example.com:5000 &", 1},
		{"dockerd --host=unix:///var/run/docker.sock &", 0},
		{"NODE_TLS_REJECT_UNAUTHORIZED=0 npm run test", 1},
		{"export NODE_TLS_REJECT_UNAUTHORIZED='0'", 1},
		{"export NODE_TLS_REJECT_UNAUTHORIZED=1", 0},
		{"export PIP_TRUSTED_HOST=pypi.example.com", 1},
		{`export PIP_TRUSTED_HOST=""`, 0},
	} {
		t.Run(tc.line, func(t *testing.T) {
			f := gl042Count(t, fmt.Sprintf("job:\n  script:\n    - >-\n      %s\n", tc.line))
			if len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %v", len(f), tc.want, f)
			}
		})
	}
}

func TestGL042_InsecureRegistryInServices(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      int
	}{
		{"job", "job:\n  services:\n    - name: docker:27-dind\n      command: [\"--insecure-registry=registry.example.com\"]\n  script: [make]\n", 1},
		{"entrypoint", "job:\n  services:\n    - name: docker:27-dind\n      entrypoint: [dockerd, --insecure-registry=registry.example.com]\n  script: [make]\n", 1},
		{"top level", "services:\n  - name: docker:27-dind\n    command: [\"--insecure-registry=registry.example.com\"]\njob:\n  script: [make]\n", 1},
		{"default", "default:\n  services:\n    - name: docker:27-dind\n      command: [\"--insecure-registry=registry.example.com\"]\njob:\n  script: [make]\n", 1},
		{"other flag", "job:\n  services:\n    - name: docker:27-dind\n      command: [\"--tlsverify\"]\n  script: [make]\n", 0},
		{"plain service", "job:\n  services:\n    - postgres:16\n  script: [make]\n", 0},
		{"shared through an anchor", ".s: &s\n  - name: docker:27-dind\n    command: [\"--insecure-registry=r\"]\na:\n  services: *s\n  script: [make]\nb:\n  services: *s\n  script: [make]\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := gl042Count(t, tc.src); len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %v", len(f), tc.want, f)
			}
		})
	}
}

func TestGL042_TLSVariables(t *testing.T) {
	for _, tc := range []struct {
		vars string
		want int
	}{
		{`NODE_TLS_REJECT_UNAUTHORIZED: "0"`, 1},
		{`NODE_TLS_REJECT_UNAUTHORIZED: 0`, 1},
		{`NODE_TLS_REJECT_UNAUTHORIZED: "1"`, 0},
		{`PIP_TRUSTED_HOST: pypi.example.com`, 1},
		{`PIP_TRUSTED_HOST: ""`, 0},
		{`PIP_INDEX_URL: https://pypi.example.com/simple`, 0},
	} {
		t.Run(tc.vars, func(t *testing.T) {
			if f := gl042Count(t, "variables:\n  "+tc.vars+"\njob:\n  script: [make]\n"); len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %v", len(f), tc.want, f)
			}
			if f := gl042Count(t, "job:\n  variables:\n    "+tc.vars+"\n  script: [make]\n"); len(f) != tc.want {
				t.Fatalf("job level: got %d findings, want %d: %v", len(f), tc.want, f)
			}
		})
	}
}
