// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import "testing"

func TestPrintedSecret(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		// Printed to the job log.
		{`echo $DEPLOY_TOKEN`, true},
		{`echo "token: ${DEPLOY_TOKEN}"`, true},
		{`printf '%s\n' "$DB_PASSWORD"`, true},
		{`print $API_KEY`, true},
		{`DEBUG=1 echo $DEPLOY_TOKEN`, true},
		{`A=1 B=2 echo $DEPLOY_TOKEN`, true},
		{`if true; then echo $DEPLOY_TOKEN; fi`, true},
		{`for i in 1; do echo $DEPLOY_TOKEN; done`, true},
		{`! echo $DEPLOY_TOKEN`, true},
		{`{ echo $DEPLOY_TOKEN; }`, true},
		{`(echo $DEPLOY_TOKEN)`, true},
		{`make build && echo $DEPLOY_TOKEN`, true},
		{`test -n "$CI_JOB_TOKEN" && echo "$CI_JOB_TOKEN"`, true},
		{`[ -n "$API_KEY" ] && echo "$DEPLOY_TOKEN"`, true},
		{`echo "${CI_JOB_TOKEN:-missing}"`, true},
		{`echo "${CI_JOB_TOKEN:+set}" "$DEPLOY_TOKEN"`, true},
		{`echo "${CI_JOB_TOKEN:+$DEPLOY_TOKEN}"`, true},
		{`bash -c "true; echo $DEPLOY_TOKEN"`, true},
		{`ssh host "cd /app && echo $DEPLOY_TOKEN"`, true},
		{`sh -c "echo hi; printf '%s' $DEPLOY_TOKEN"`, true},
		{`bash -eo pipefail -c "true; echo $DEPLOY_TOKEN"`, true},
		{`bash -o pipefail -c "true; echo $DEPLOY_TOKEN"`, true},
		{`bash --login -c "true; echo $DEPLOY_TOKEN"`, true},
		{`eval "true; echo $DEPLOY_TOKEN"`, true},
		{`su app -c "cd /app; echo $DEPLOY_TOKEN"`, true},

		// Not printed.
		{`$DEPLOY_TOKEN`, false},
		{`cat $DEPLOY_TOKEN`, false},
		{`docker login -p $DEPLOY_TOKEN`, false},
		{`echo $DEPLOY_TOKEN > token.txt`, false},
		{`echo $DEPLOY_TOKEN >> ~/.netrc`, false},
		{`echo $DEPLOY_TOKEN | docker login --password-stdin`, false},
		{`TOKEN=$(echo $DEPLOY_TOKEN)`, false},
		{`diff <(echo $DEPLOY_TOKEN) expected`, false},
		{`echo '$DEPLOY_TOKEN'`, false},
		{`git config credential.helper "!echo $DEPLOY_TOKEN"`, false},
		{`[ -n "$DEPLOY_TOKEN" ] && echo set`, false},
		{`test -n "$CI_JOB_TOKEN" && echo "token is set"`, false},
		{`echo ${DEPLOY_TOKEN:+set}`, false},
		{`echo "${CI_JOB_TOKEN:+ (set)}"`, false},
		{`echo "${CI_JOB_TOKEN:+ (set)}" > check.log`, false},
		{`bash -c "echo $DEPLOY_TOKEN" > token.txt`, false},
		{`ssh host "echo $DEPLOY_TOKEN" | docker login --password-stdin`, false},
		{`ssh host 'echo $DEPLOY_TOKEN'`, false},
		{`bash -eo pipefail -c "true; echo $DEPLOY_TOKEN" > token.txt`, false},
		{`eval 'true; echo $DEPLOY_TOKEN'`, false},
		{`echo $USERNAME`, false},
		{`echo $DEPLOY_TOKENIZER_URL`, false},
		{`echo $GPG_KEY_ID`, false},
		{`echo "$DOCKER_PASSWORD_FILE"`, false},
		{`echo ${VAULT_TOKEN_PATH}`, false},
		{`echo $AWS_ACCESS_KEY_ID`, false},
		{`echo $SECRET_KEY_BASE`, true},
		{`echo $AWS_SECRET_ACCESS_KEY`, true},
		{`echo $MY_TOKENS`, true},
		{`echo $GPG_KEY_ID $DEPLOY_TOKEN`, true},
	}
	for _, tt := range tests {
		if _, got := printedSecret(tt.line); got != tt.want {
			t.Errorf("printedSecret(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestSegmentPrintCommand(t *testing.T) {
	tests := []struct {
		head string
		want string
	}{
		{"echo ", "echo"},
		{"  X=1 then printf ", "printf"},
		{"", ""},
		{"X=1 ", ""},
		{"{ ( ", ""},
		{"echo_wrapper ", ""},
	}
	for _, tt := range tests {
		if got := segmentPrintCommand(tt.head); got != tt.want {
			t.Errorf("segmentPrintCommand(%q) = %q, want %q", tt.head, got, tt.want)
		}
	}
}

func TestIsSecretName(t *testing.T) {
	tests := map[string]bool{
		"DEPLOY_TOKEN":          true,
		"CI_JOB_TOKEN":          true,
		"SECRET_KEY_BASE":       true,
		"DB_PASSWORD":           true,
		"SSH_PRIVATE_KEY":       true,
		"TLS_CERT":              true,
		"GPG_KEY_ID":            false,
		"DOCKER_PASSWORD_FILE":  false,
		"DEPLOY_TOKENIZER_URL":  false,
		"VAULT_TOKEN_PATH":      false,
		"SERVICE_KEY_NAME":      false,
		"DOCKER_TLS_CERTDIR":    false,
		"SSH_KEY_DIR":           false,
		"TOKEN":                 false, // nothing before the indicator
		"BYPASS":                false,
		"API_TOKEN_EXPIRES_AT":  false,
		"REGISTRY_PASS_USER":    false,
		"API_KEY_IDENTIFIER":    true, // _IDENTIFIER is not _ID
		"WEBHOOK_SECRET_HEADER": true,
	}
	for name, want := range tests {
		if got := isSecretName(name); got != want {
			t.Errorf("isSecretName(%q) = %v, want %v", name, got, want)
		}
	}
}
