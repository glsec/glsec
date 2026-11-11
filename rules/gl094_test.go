// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings094(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL094.Check(doc.Root, "test.yml")
}

func TestGL094_ExfilPrep(t *testing.T) {
	for _, line := range []string{
		"cat ~/.ssh/id_rsa | base64",
		"base64 ~/.ssh/id_rsa",
		"cat ~/.ssh/id_ed25519 | xxd",
		"tar czf keys.tgz ~/.ssh",
		"zip -r keys.zip ~/.ssh",
		"cp ~/.ssh/id_rsa /tmp/exfil/",
		"mv ~/.ssh/id_ecdsa /artifacts/",
		"install -m600 ~/.ssh/id_rsa /tmp/pickup/",
		"gzip ~/.ssh/id_dsa",
		"cat /root/.ssh/id_rsa | base64 -w0",
	} {
		t.Run(line, func(t *testing.T) {
			f := findings094(t, "j:\n  script:\n    - "+line+"\n")
			if len(f) == 0 {
				t.Fatalf("expected a GL094 finding for %q", line)
			}
			if f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "private key") {
				t.Errorf("unexpected finding %+v", f[0])
			}
		})
	}
}

func TestGL094_NoFinding(t *testing.T) {
	for _, line := range []string{
		"cat ~/.ssh/id_rsa",                      // bare read
		"echo \"$SSH_KEY\" > ~/.ssh/id_rsa",      // write — GL032's
		"chmod 600 ~/.ssh/id_rsa",                // using
		"ssh-add ~/.ssh/id_rsa",                  // using
		"ssh-keygen -t ed25519 -f ~/.ssh/id_rsa", // generating
		"cat ~/.ssh/id_rsa.pub | base64",         // public key
		"cp /tmp/key ~/.ssh/id_rsa",              // written into place, not read off
		"tar czf logs.tgz ./logs",                // unrelated archive
		"base64 config.json",                     // unrelated encode
		"echo \"cat ~/.ssh/id_rsa | base64\"",    // quoted prose, not a command
		"cat ~/.ssh/known_hosts | base64",        // a non-key file under .ssh
	} {
		t.Run(line, func(t *testing.T) {
			f := findings094(t, "j:\n  script:\n    - "+line+"\n")
			if len(f) != 0 {
				t.Fatalf("expected no GL094 finding for %q, got %+v", line, f)
			}
		})
	}
}

func TestGL094_JobAndSeverity(t *testing.T) {
	f := findings094(t, "deploy:\n  script:\n    - make build\n    - base64 ~/.ssh/id_rsa\n")
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	if f[0].Job != "deploy" || f[0].Line != 4 {
		t.Errorf("got job %q line %d, want deploy line 4", f[0].Job, f[0].Line)
	}
}
