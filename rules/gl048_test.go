package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings048(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL048.Check(doc.Root, "test.yml")
}

func TestGL048_SSHOptionNo(t *testing.T) {
	f := findings048(t, `
deploy:
  script:
    - ssh -o StrictHostKeyChecking=no deploy@$HOST "systemctl restart app"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL048_SSHOptionOff(t *testing.T) {
	f := findings048(t, `
deploy:
  script:
    - ssh -o StrictHostKeyChecking=off deploy@$HOST "systemctl restart app"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for StrictHostKeyChecking=off, got %d", len(f))
	}
}

func TestGL048_SCPOption(t *testing.T) {
	f := findings048(t, `
deploy:
  script:
    - scp -o StrictHostKeyChecking=no dist/ deploy@$HOST:/var/www/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for scp with StrictHostKeyChecking=no, got %d", len(f))
	}
}

func TestGL048_SFTPOption(t *testing.T) {
	f := findings048(t, `
deploy:
  script:
    - sftp -o StrictHostKeyChecking=no deploy@$HOST
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sftp with StrictHostKeyChecking=no, got %d", len(f))
	}
}

func TestGL048_RsyncOption(t *testing.T) {
	f := findings048(t, `
deploy:
  script:
    - rsync -e "ssh -o StrictHostKeyChecking=no" dist/ deploy@$HOST:/var/www/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for rsync with StrictHostKeyChecking=no, got %d", len(f))
	}
}

func TestGL048_EchoToSSHConfig(t *testing.T) {
	f := findings048(t, `
deploy:
  before_script:
    - echo "StrictHostKeyChecking no" >> ~/.ssh/config
  script:
    - ssh deploy@$HOST "deploy.sh"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for echo StrictHostKeyChecking no to config, got %d", len(f))
	}
}

func TestGL048_EchoOffToSSHConfig(t *testing.T) {
	f := findings048(t, `
deploy:
  script:
    - echo "StrictHostKeyChecking off" >> ~/.ssh/config
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for StrictHostKeyChecking off, got %d", len(f))
	}
}

func TestGL048_YesValueNoFinding(t *testing.T) {
	f := findings048(t, `
deploy:
  script:
    - ssh -o StrictHostKeyChecking=yes deploy@$HOST "systemctl restart app"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for StrictHostKeyChecking=yes, got %d", len(f))
	}
}

func TestGL048_KnownHostsSetupNoFinding(t *testing.T) {
	f := findings048(t, `
deploy:
  before_script:
    - mkdir -p ~/.ssh && chmod 700 ~/.ssh
    - echo "$SSH_KNOWN_HOSTS" >> ~/.ssh/known_hosts
    - chmod 644 ~/.ssh/known_hosts
  script:
    - ssh deploy@$HOST "systemctl restart app"
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for proper known_hosts setup, got %d", len(f))
	}
}

func TestGL048_GlobalBeforeScript(t *testing.T) {
	f := findings048(t, `
before_script:
  - echo "StrictHostKeyChecking no" >> ~/.ssh/config

deploy:
  script:
    - ssh deploy@$HOST "deploy.sh"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for global before_script, got %d", len(f))
	}
}

func TestGL048_JobNameInFinding(t *testing.T) {
	f := findings048(t, `
deploy-prod:
  script:
    - ssh -o StrictHostKeyChecking=no deploy@$HOST "restart"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Job != "deploy-prod" {
		t.Errorf("expected job 'deploy-prod', got %q", f[0].Job)
	}
}
