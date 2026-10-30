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

func findings088(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL088.Check(doc.Root, "test.yml")
}

// Tokens are assembled from split literals so no contiguous token appears in
// the source, which GitHub push protection would block.
var (
	sonarToken  = "sq" + "p_" + strings.Repeat("0123456789abcdef", 2) + "01234567"
	gitlabToken = "gl" + "pat-" + strings.Repeat("a1B2", 5)
	npmToken    = "np" + "m_" + strings.Repeat("a", 36)
	tsToken     = "tskey-" + "auth-" + "k" + "Ab12Cd34" + "CNTRL-" + strings.Repeat("a", 32)
)

func TestGL088_TokenInCommand(t *testing.T) {
	cases := map[string]struct {
		line, label string
	}{
		"sonar flag":     {"sonar-scanner -Dsonar.token=" + sonarToken, "SonarQube token"},
		"header":         {`curl -H "PRIVATE-TOKEN: ` + gitlabToken + `" https://gitlab.example.com/api/v4/projects`, "GitLab PAT"},
		"export":         {"export NPM_TOKEN=" + npmToken, "npm access token"},
		"single quotes":  {"npm config set //registry.npmjs.org/:_authToken '" + npmToken + "'", "npm access token"},
		"end of line":    {"echo " + gitlabToken, "GitLab PAT"},
		"aws key in env": {"AWS_ACCESS_KEY_ID=AKIA" + strings.Repeat("Q", 16) + " aws s3 ls", "AWS access key"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings088(t, fmt.Sprintf("build:\n  script:\n    - %q\n", tc.line))
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Severity != finding.Error || f[0].Job != "build" || f[0].Line != 3 {
				t.Errorf("unexpected finding: %+v", f[0])
			}
			if !strings.Contains(f[0].Message, tc.label) {
				t.Errorf("expected %q in message, got %q", tc.label, f[0].Message)
			}
		})
	}
}

// The auth key follows --authkey=, so the boundary before it is "="
// rather than whitespace; the token still ends at end of line.
func TestGL088_TailscaleAuthkey(t *testing.T) {
	f := findings088(t, fmt.Sprintf("build:\n  script:\n    - %q\n", "tailscale up --authkey="+tsToken))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "Tailscale auth key") {
		t.Errorf("expected %q in message, got %q", "Tailscale auth key", f[0].Message)
	}
}

func TestGL088_EveryTokenOnce(t *testing.T) {
	f := findings088(t, fmt.Sprintf(`
build:
  script:
    - "tool --a %s %s"
`, gitlabToken, sonarToken))
	if len(f) != 2 {
		t.Fatalf("expected one finding per token, got %d: %v", len(f), f)
	}
}

func TestGL088_BlockScalarLine(t *testing.T) {
	f := findings088(t, fmt.Sprintf(`
build:
  script:
    - |
      echo start
      sonar-scanner -Dsonar.token=%s
`, sonarToken))
	if len(f) != 1 || f[0].Line != 6 {
		t.Fatalf("expected 1 finding on line 6, got %+v", f)
	}
}

func TestGL088_AllScriptSections(t *testing.T) {
	f := findings088(t, fmt.Sprintf(`
before_script:
  - echo %[1]s
default:
  after_script:
    - echo %[1]s
build:
  hooks:
    pre_get_sources_script:
      - echo %[1]s
  script:
    - echo ok
  run:
    - name: step
      script: echo %[1]s
`, gitlabToken))
	if len(f) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(f))
	}
}

func TestGL088_NoFinding(t *testing.T) {
	lines := []string{
		"sonar-scanner -Dsonar.token=$SONAR_TOKEN",
		"sonar-scanner -Dsonar.token=${SONAR_TOKEN}",
		"echo " + sonarToken[:len(sonarToken)-1],      // 39 hex chars
		"echo x" + npmToken,                           // inside a longer word
		"echo " + npmToken + "b",                      // 37 chars
		"echo gl" + "pat-your-token-here-please",      // placeholder
		"echo AKIA" + "IOSFODNN7EXAMPLE",              // placeholder
		`jq -e '.type == "service_account"' key.json`, // GCP pattern is variables-only
		`grep -q '"type": "service_account"' key.json`,
	}
	for _, line := range lines {
		f := findings088(t, fmt.Sprintf("build:\n  script:\n    - %q\n", line))
		if len(f) != 0 {
			t.Errorf("expected no finding for %q, got %v", line, f)
		}
	}
}

// Every sample GL006 finds in variables: is also found in a script line, so
// rewriting the anchors broke none of those patterns.
func TestGL088_AllFormats(t *testing.T) {
	if got, want := len(scriptSecretPatterns), len(secretPatterns)-len(scriptOnlyInVariables); got != want {
		t.Errorf("%d script patterns, want %d", got, want)
	}
	for name, tc := range anchoredFormatCases() {
		t.Run(name, func(t *testing.T) {
			f := findings088(t, fmt.Sprintf("build:\n  script:\n    - %q\n", "deploy --token "+tc.value+" --yes"))
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if !strings.Contains(f[0].Message, tc.label) {
				t.Errorf("expected %q in message, got %q", tc.label, f[0].Message)
			}
		})
	}
}

// A plain scalar folds its lines; the token's own line can't be traced back,
// so the finding is reported where the scalar starts, not a line too early
// or too late (#753).
func TestGL088_FoldedScalarLine(t *testing.T) {
	f := findings088(t, fmt.Sprintf(`
build:
  script:
    - echo start


      sonar-scanner -Dsonar.token=%s
`, sonarToken))
	if len(f) != 1 || f[0].Line != 7 {
		t.Fatalf("expected 1 finding on the token's line 7, got %+v", f)
	}
}
