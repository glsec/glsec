// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestGL031(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantHits int
	}{
		{
			name: "top-level DOCKER_TLS_CERTDIR empty string",
			yaml: `variables:
  DOCKER_HOST: tcp://docker:2375
  DOCKER_TLS_CERTDIR: ""`,
			wantHits: 1,
		},
		{
			name: "job-level DOCKER_TLS_CERTDIR empty string",
			yaml: `build:
  services:
    - docker:dind
  variables:
    DOCKER_TLS_CERTDIR: ""
  script:
    - docker build .`,
			wantHits: 1,
		},
		{
			name: "DOCKER_TLS_CERTDIR set to /certs — safe",
			yaml: `variables:
  DOCKER_TLS_CERTDIR: "/certs"`,
			wantHits: 0,
		},
		{
			name: "no DOCKER_TLS_CERTDIR — safe",
			yaml: `variables:
  SOME_VAR: "value"`,
			wantHits: 0,
		},
		{
			name: "top-level and job-level both empty — two findings",
			yaml: `variables:
  DOCKER_TLS_CERTDIR: ""
build:
  variables:
    DOCKER_TLS_CERTDIR: ""
  script:
    - docker build .`,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte(tt.yaml), "test.yml")
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			findings := GL031.Check(doc.Root, "test.yml")
			if len(findings) != tt.wantHits {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantHits)
				for _, f := range findings {
					t.Logf("  finding: %s", f.Message)
				}
			}
		})
	}
}

// A job that clears DOCKER_HOST or points it at a Unix socket uses the
// runner's daemon; its empty DOCKER_TLS_CERTDIR turns no TLS off (#992).
func TestGL031_RunnerSocket(t *testing.T) {
	for host, want := range map[string]int{
		`""`:                          0,
		"unix:///var/run/docker.sock": 0,
		"tcp://docker:2375":           1,
	} {
		doc, err := parser.Parse([]byte("local-docker:\n  image: docker:27.3.1\n  variables:\n    DOCKER_HOST: "+host+"\n    DOCKER_TLS_CERTDIR: \"\"\n  script: [docker info]\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL031.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("DOCKER_HOST %s: got %d findings, want %d", host, got, want)
		}
	}
}
