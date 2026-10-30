// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings021(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL021.Check(doc.Root, "test.yml")
}

func TestGL021_EchoToken(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $MY_API_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL021_EchoPassword(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $DEPLOY_PASSWORD
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for PASSWORD variable, got %d", len(f))
	}
}

func TestGL021_EchoCIJobToken(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $CI_JOB_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_JOB_TOKEN, got %d", len(f))
	}
}

func TestGL021_PrintfSecret(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - printf "%s\n" "$API_SECRET"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for printf with secret, got %d", len(f))
	}
}

func TestGL021_EchoKey(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $AWS_SECRET_ACCESS_KEY
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for _KEY variable, got %d", len(f))
	}
}

func TestGL021_SafePresenceCheck_NoFinding(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - '[ -n "$MY_API_TOKEN" ] && echo "token set"'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for presence check, got %d", len(f))
	}
}

func TestGL021_NoSecretVar_NoFinding(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo "Branch is $CI_COMMIT_REF_NAME"
    - echo "Job ID: $CI_JOB_ID"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for non-secret variables, got %d", len(f))
	}
}

func TestGL021_NoPrintCommand_NoFinding(t *testing.T) {
	f := findings021(t, `
deploy:
  script:
    - curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/deploy
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when no print command present, got %d", len(f))
	}
}

func TestGL021_BraceExpansion(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo ${DEPLOY_PASSWORD}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace expansion, got %d", len(f))
	}
}

func TestGL021_BeforeScript(t *testing.T) {
	f := findings021(t, `
debug:
  before_script:
    - echo $CI_REGISTRY_PASSWORD
  script:
    - docker login
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL021_MultipleFindings(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $API_TOKEN
    - echo $DEPLOY_PASSWORD
    - echo "non-secret info"
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL021_PasswordStdin_NoFinding(t *testing.T) {
	// `echo "$SECRET" | docker login --password-stdin` pipes the value to the
	// command's stdin, not the job log — the idiom GL029 recommends.
	f := findings021(t, `
build:
  before_script:
    - echo "${CI_REGISTRY_PASSWORD}" | docker login --username "${CI_REGISTRY_USER}" --password-stdin "${CI_REGISTRY}"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for --password-stdin idiom, got %d", len(f))
	}
}

func TestGL021_BlockScalarCrossLine_NoFinding(t *testing.T) {
	// echo (non-secret) and the secret var are on different lines of one block
	// scalar — the secret is passed as a curl header, never printed.
	f := findings021(t, `
deps:
  script:
    - |
      if curl -H "JOB-TOKEN: $CI_JOB_TOKEN" -sLO "$PACKAGE_URL"; then
        echo "Found dependencies in package registry."
      fi
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when echo and secret are on different lines, got %d", len(f))
	}
}

func TestGL021_BlockScalarSameLine_Finding(t *testing.T) {
	// A real leak inside a block scalar (echo + secret on the same line) must
	// still be caught.
	f := findings021(t, `
deps:
  script:
    - |
      echo "starting"
      echo "$DEPLOY_TOKEN"
      echo "done"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for echo of secret inside block scalar, got %d", len(f))
	}
}

func TestGL021_RedirectToFile_NoFinding(t *testing.T) {
	f := findings021(t, `
deploy:
  script:
    - echo "$AWS_ACCESS_KEY_ID" >> ~/.s3cfg
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for redirect to file, got %d", len(f))
	}
}

func TestGL021_PipeToConsumer_NoFinding(t *testing.T) {
	f := findings021(t, `
deploy:
  script:
    - echo "$CARGO_TOKEN" | cargo login
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for echo piped into a command, got %d", len(f))
	}
}

func TestGL021_SshAddStdin_NoFinding(t *testing.T) {
	// The very idiom GL032's message recommends; the key never hits the log.
	f := findings021(t, `
deploy:
  script:
    - echo "$SSH_PRIVATE_KEY" | tr -d '\r' | ssh-add -
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for echo piped into ssh-add, got %d", len(f))
	}
}

func TestGL021_ProcessSubstitution_NoFinding(t *testing.T) {
	f := findings021(t, `
deploy:
  script:
    - ssh-add <(echo "$DEPLOY_SSH_KEY")
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for process substitution, got %d", len(f))
	}
}

func TestGL021_CommandSubstitution_NoFinding(t *testing.T) {
	f := findings021(t, `
query:
  script:
    - 'export AUTH="Basic $(echo -n "$MIMIR_API_USER:$MIMIR_API_KEY" | base64)"'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for command substitution, got %d", len(f))
	}
}

func TestGL021_SingleQuotedLiteral_NoFinding(t *testing.T) {
	f := findings021(t, `
notice:
  script:
    - "echo '$GITLAB_STATE_CLEANER_TOKEN is deprecated'"
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for single-quoted literal, got %d", len(f))
	}
}

func TestGL021_PresenceCheckTestN_NoFinding(t *testing.T) {
	f := findings021(t, `
guard:
  script:
    - 'test -n "$GITLAB_TOKEN" || { echo "GITLAB_TOKEN not set"; exit 1; }'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for test -n presence check, got %d", len(f))
	}
}

func TestGL021_SecretAsCommandArg_NoFinding(t *testing.T) {
	// echo is an unrelated warning on the same line; the secret is an argument
	// of a different command, not printed.
	f := findings021(t, `
publish:
  script:
    - 'gnome-extensions upload --password "$EGO_PASSWORD" "$FILE" || { echo "upload failed"; exit 1; }'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when secret is an arg of a non-print command, got %d", len(f))
	}
}

func TestGL021_CredentialHelperString_NoFinding(t *testing.T) {
	// The echo lives inside a git credential-helper string argument; git
	// consumes the helper's output, it is never printed to the log.
	f := findings021(t, `
update:
  before_script:
    - 'git config --local credential.helper "!echo \"password=$LOCKFILE_UPDATE_GITLAB_TOKEN\"; :"'
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for echo inside credential.helper string, got %d", len(f))
	}
}

func TestGL021_BraceVarRedirect_NoFinding(t *testing.T) {
	// Regression: the closing `}` of ${VAR} must not be treated as a command
	// separator, or the trailing redirect is missed and this is flagged.
	f := findings021(t, `
deploy:
  script:
    - echo "secret_key = ${AWS_SECRET_ACCESS_KEY}" >> ~/.s3cfg
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for brace-var redirect to file, got %d", len(f))
	}
}

func TestGL021_EchoWithTextPrefix_Finding(t *testing.T) {
	// A genuine leak: the secret is printed to the log alongside text.
	f := findings021(t, `
debug:
  script:
    - echo "token=$API_TOKEN"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for echoed secret with text, got %d", len(f))
	}
}

func TestGL021_BlockScalarLineNumber(t *testing.T) {
	// The secret echo is on file line 5; a block scalar's node.Line points at
	// the `- |` line (3), so the offset must account for the indicator line.
	f := findings021(t, `job:
  script:
    - |
      echo "start"
      echo "$DEPLOY_TOKEN"`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Line != 5 {
		t.Errorf("expected line 5, got %d", f[0].Line)
	}
}

func TestGL021_LineNumber(t *testing.T) {
	f := findings021(t, `
debug:
  script:
    - echo $MY_API_TOKEN
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL021_PowerShellPrintedSecrets(t *testing.T) {
	for _, tc := range []struct {
		name, script, variable string
	}{
		{"echo environment variable", `echo $env:DEPLOY_TOKEN`, "$env:DEPLOY_TOKEN"},
		{"braced environment variable", `echo ${env:DEPLOY_TOKEN}`, "${env:DEPLOY_TOKEN}"},
		{"mixed-case environment drive", `echo $eNv:DEPLOY_TOKEN`, "$eNv:DEPLOY_TOKEN"},
		{"host output", `Write-Host "token is $env:DEPLOY_TOKEN"`, "$env:DEPLOY_TOKEN"},
		{"success output", `Write-Output ${ENV:DEPLOY_PASSWORD}`, "${ENV:DEPLOY_PASSWORD}"},
		{"information output", `Write-Information $env:API_SECRET -InformationAction Continue`, "$env:API_SECRET"},
		{"write alias", `write $env:SSH_PRIVATE_KEY`, "$env:SSH_PRIVATE_KEY"},
		{"mixed-case command", `wRiTe-HoSt $env:DEPLOY_TOKEN`, "$env:DEPLOY_TOKEN"},
		{"mixed-case output command", `WRITE-OUTPUT $env:DEPLOY_TOKEN`, "$env:DEPLOY_TOKEN"},
		{"mixed-case information command", `WRITE-INFORMATION $env:DEPLOY_TOKEN`, "$env:DEPLOY_TOKEN"},
		{"mixed-case alias", `WrItE $env:DEPLOY_TOKEN`, "$env:DEPLOY_TOKEN"},
		{"mixed-case secret name", `Write-Host ${Env:Deploy_Token}`, "${Env:Deploy_Token}"},
		{"unscoped PowerShell variable", `Write-Host $DEPLOY_TOKEN`, "$DEPLOY_TOKEN"},
		{"non-secret before secret", `Write-Output $env:GPG_KEY_ID $env:DEPLOY_TOKEN`, "$env:DEPLOY_TOKEN"},
		{"host output bypasses pipeline", `Write-Host $env:DEPLOY_TOKEN | Out-Null`, "$env:DEPLOY_TOKEN"},
		{"host output bypasses success redirection", `Write-Host $env:DEPLOY_TOKEN > token.txt`, "$env:DEPLOY_TOKEN"},
		{"host output bypasses capture", `$value = $(Write-Host $env:DEPLOY_TOKEN)`, "$env:DEPLOY_TOKEN"},
		{"information output bypasses pipeline", `Write-Information $env:DEPLOY_TOKEN -InformationAction Continue | Out-Null`, "$env:DEPLOY_TOKEN"},
		{"quoted redirect is text", `Write-Host "literal 6> $env:DEPLOY_TOKEN"`, "$env:DEPLOY_TOKEN"},
		{"escaped backtick still expands", "Write-Host \"``$env:DEPLOY_TOKEN\"", "$env:DEPLOY_TOKEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings021(t, "deploy:\n  tags: [windows]\n  script:\n    - "+strconv.Quote(tc.script)+"\n")
			if len(f) != 1 {
				t.Fatalf("got %d findings, want 1", len(f))
			}
			want := finding.Finding{
				RuleID: "GL021", Severity: finding.Warn, Job: "deploy", File: "test.yml", Line: 4, Col: 7,
				Message: "script prints secret variable " + tc.variable + " — value may appear in job logs",
			}
			if f[0] != want {
				t.Errorf("got %+v, want %+v", f[0], want)
			}
		})
	}
}

func TestGL021_PowerShellClean(t *testing.T) {
	for _, script := range []string{
		`Write-Host '$env:DEPLOY_TOKEN'`,
		`Write-Output '${env:DEPLOY_TOKEN}'`,
		`Write-Host $env:GPG_KEY_ID`,
		`Write-Host ${env:DOCKER_PASSWORD_FILE}`,
		`Write-Host $env:DEPLOY_TOKENIZER_URL`,
		`Write-Host $env:DOCKER_TLS_CERTDIR`,
		`Write-Host $env:CI_RUNNER_SHORT_TOKEN`,
		`Write-Host $env:deploy_token_url`,
		`Write-Host $env:ci_runner_short_token`,
		`Write-Host $env:CI_COMMIT_BRANCH`,
		`Invoke-WebRequest -Headers $env:API_TOKEN https://example.com`,
		`my-Write-Host $env:DEPLOY_TOKEN`,
		`git config helper "Write-Host $env:DEPLOY_TOKEN"`,
		`echo $env:DEPLOY_TOKEN | docker login --password-stdin`,
		`Write-Output ${env:DEPLOY_TOKEN} > token.txt`,
		`Write-Output $env:DEPLOY_TOKEN | Set-Content token.txt`,
		`Write-Host $env:DEPLOY_TOKEN 6> $null`,
		`Write-Host $env:DEPLOY_TOKEN *> $null`,
		`Write-Host $env:DEPLOY_TOKEN 6> 'private log.txt'`,
		`Write-Information ${env:DEPLOY_TOKEN} -InformationAction Continue 6>> info.log`,
		"Write-Host \"`$env:DEPLOY_TOKEN\"",
		`echo $deploy_token`,
	} {
		t.Run(script, func(t *testing.T) {
			f := findings021(t, "deploy:\n  tags: [windows]\n  script:\n    - "+strconv.Quote(script)+"\n")
			if len(f) != 0 {
				t.Errorf("got %v, want no findings", f)
			}
		})
	}
}

func TestGL021_EmptyQuotedCommandFragment(t *testing.T) {
	for _, script := range []string{`echo'' "$DEPLOY_TOKEN"`, `''echo "$DEPLOY_TOKEN"`, `printf'' '%s' "$DEPLOY_TOKEN"`} {
		t.Run(script, func(t *testing.T) {
			f := findings021(t, "debug:\n  script:\n    - "+strconv.Quote(script)+"\n")
			if len(f) != 1 {
				t.Fatalf("got %d findings, want 1 for POSIX quoted command fragment", len(f))
			}
		})
	}
}

// A substring expansion is shown with its closing brace (#977).
func TestGL021_SubstringExpansionName(t *testing.T) {
	doc, err := parser.Parse([]byte("job:\n  script:\n    - echo \"prefix ${PUBLISH_TOKEN:0:4}\"\n"), "test.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := GL021.Check(doc.Root, "test.yml")
	if len(f) != 1 || !strings.Contains(f[0].Message, "${PUBLISH_TOKEN} ") {
		t.Errorf("got %v, want a message naming ${PUBLISH_TOKEN}", f)
	}
}

// An escaped reference prints its name, and a group or subshell whose output
// is redirected or piped doesn't print to the log (#982).
func TestGL021_EscapesAndDivertedGroups(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{`echo "//registry.example.com/:_authToken=\${CI_JOB_TOKEN}" >> .npmrc`, 0},
		{`echo "token is \$CI_JOB_TOKEN"`, 0},
		{`{ echo "//registry.example.com/:_authToken=${CI_JOB_TOKEN}"; } >> .npmrc`, 0},
		{`( echo "$SSH_PRIVATE_KEY" ) | ssh-add -`, 0},
		{`{ echo "$GPG_PRIVATE_KEY"; } | gpg --import`, 0},
		{`{ echo "$API_TOKEN"; }`, 1},
		{`( echo "$API_TOKEN" ) || true`, 1},
		{`echo "$API_TOKEN"`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - '"+tc.line+"'\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL021.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.line, got, tc.want)
		}
	}
}

// An escaped character outside quotes doesn't open a quote (#982).
func TestGroupOutputDiverted_Escape(t *testing.T) {
	s := `{ echo \"$NPM_TOKEN; } >> .npmrc`
	if !groupOutputDiverted(s, strings.Index(s, "$NPM_TOKEN")) {
		t.Error("the group's output goes to .npmrc")
	}
}
