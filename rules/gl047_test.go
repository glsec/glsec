package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings047(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL047.Check(doc.Root, "test.yml")
}

func TestGL047_BasicSSHRoot(t *testing.T) {
	f := findings047(t, `
deploy:
  script:
    - ssh root@$PRODUCTION_HOST "systemctl restart app"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL047_SSHRootWithKey(t *testing.T) {
	f := findings047(t, `
deploy:
  script:
    - ssh -i /tmp/key root@192.168.1.1 "cd /app && git pull"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ssh -i key root@host, got %d", len(f))
	}
}

func TestGL047_SSHRootWithPort(t *testing.T) {
	f := findings047(t, `
deploy:
  script:
    - ssh -p 2222 root@$DEPLOY_HOST "make deploy"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ssh -p port root@host, got %d", len(f))
	}
}

func TestGL047_SSHRootWithOptions(t *testing.T) {
	f := findings047(t, `
deploy:
  script:
    - ssh -o StrictHostKeyChecking=no root@server.example.com "deploy.sh"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for ssh -o options root@host, got %d", len(f))
	}
}

func TestGL047_NonRootUserNoFinding(t *testing.T) {
	f := findings047(t, `
deploy:
  script:
    - ssh deploy@$PRODUCTION_HOST "systemctl restart app"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for non-root user, got %d", len(f))
	}
}

func TestGL047_NoSSHNoFinding(t *testing.T) {
	f := findings047(t, `
build:
  script:
    - make build
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings without ssh, got %d", len(f))
	}
}

func TestGL047_SSHRootInBeforeScript(t *testing.T) {
	f := findings047(t, `
deploy:
  before_script:
    - ssh root@$HOST "prepare"
  script:
    - ./deploy.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for root ssh in before_script, got %d", len(f))
	}
}

func TestGL047_JobNameInFinding(t *testing.T) {
	f := findings047(t, `
deploy-prod:
  script:
    - ssh root@$HOST "restart"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Job != "deploy-prod" {
		t.Errorf("expected job 'deploy-prod', got %q", f[0].Job)
	}
}

func TestGL047_RootInHostnameNoFinding(t *testing.T) {
	f := findings047(t, `
deploy:
  script:
    - ssh deploy@rootserver.example.com "restart"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings when 'root' only appears in hostname, got %d", len(f))
	}
}
