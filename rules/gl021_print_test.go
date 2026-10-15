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
		{`echo ${DEPLOY_TOKEN:+set}`, false},
		{`echo $USERNAME`, false},
	}
	for _, tt := range tests {
		if _, got := printedSecret(tt.line); got != tt.want {
			t.Errorf("printedSecret(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestSegmentCommandPrints(t *testing.T) {
	tests := []struct {
		head string
		want bool
	}{
		{"echo ", true},
		{"  X=1 then printf ", true},
		{"", false},
		{"X=1 ", false},
		{"{ ( ", false},
		{"echo_wrapper ", false},
	}
	for _, tt := range tests {
		if got := segmentCommandPrints(tt.head); got != tt.want {
			t.Errorf("segmentCommandPrints(%q) = %v, want %v", tt.head, got, tt.want)
		}
	}
}
