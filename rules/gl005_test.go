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

func findings005(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL005.Check(doc.Root, "test.yml")
}

func TestGL005_EnvFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .env file, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_PemFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - deploy-key.pem
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .pem file, got %d", len(f))
	}
}

func TestGL005_NoExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing expire_in, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity for missing expiry")
	}
}

func TestGL005_SensitiveAndNoExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
      - dist/
`)
	// .env finding (Error) + no expire_in (Warn)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL005_SafeArtifactWithExpiry(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/
      - coverage.xml
    expire_in: 7 days
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for safe artifact with expiry, got %d", len(f))
	}
}

func TestGL005_KeyFile(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - secrets/api.key
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .key file, got %d", len(f))
	}
}

func TestGL005_SecretInPath(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - output/db_password.txt
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for password in filename, got %d", len(f))
	}
}

func TestGL005_TerraformState(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - terraform.tfstate
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for tfstate, got %d", len(f))
	}
}

func TestGL005_SecretDetectionReportNoFinding(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - gl-secret-detection-report.json
    expire_in: 1 week
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for the secret detection report, got %d: %+v", len(f), f)
	}
}

func TestGL005_SecretDetectionRulesetNoFinding(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - secret-detection-rules.zip
    expire_in: 1 week
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for the ruleset bundle, got %d: %+v", len(f), f)
	}
}

func TestGL005_SecretDetectionReportSubdirNoFinding(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - tmp/gl-secret-detection-report.json
    expire_in: 1 week
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding for the report under tmp/, got %d: %+v", len(f), f)
	}
}

func TestGL005_ReportArtifactAlongsideRealSecretStillFires(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - gl-secret-detection-report.json
      - .env
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for .env only, got %d: %+v", len(f), f)
	}
	if !strings.Contains(f[0].Message, ".env") {
		t.Errorf("expected the finding to be about .env, got %q", f[0].Message)
	}
}

func TestGL005_DefaultBlockSensitivePath(t *testing.T) {
	f := findings005(t, `
default:
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for sensitive path in default: artifacts:, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_DefaultBlockNoExpiry(t *testing.T) {
	f := findings005(t, `
default:
  artifacts:
    paths:
      - dist/

build:
  script: [make]
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing expire_in in default: artifacts:, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL005_AbsolutePath(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - /etc/passwd
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for absolute path, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_PathTraversal(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - ../../etc/shadow
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for path traversal, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_UserControlledVarNoFinding(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/$CI_COMMIT_REF_NAME
    expire_in: 1 day
`)
	if len(f) != 0 {
		t.Fatalf("expected no findings for common branch-based artifact path, got %d", len(f))
	}
}

func TestGL005_ExcludePath(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - dist/
    exclude:
      - ../secrets.env
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for traversal in exclude, got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_AbsolutePathWithVar(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - /tmp/$CI_COMMIT_REF_NAME
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (absolute path only), got %d", len(f))
	}
	if f[0].Severity != finding.Error {
		t.Errorf("expected Error severity")
	}
}

func TestGL005_NoArtifacts(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
`)
	if len(f) != 0 {
		t.Errorf("expected no findings when no artifacts block, got %d", len(f))
	}
}

func TestGL005_LineNumbers(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths:
      - .env.production
    expire_in: 1 week
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL005_BroadArtifactPaths(t *testing.T) {
	for _, tc := range []struct {
		path string
		risk string
	}{
		{".", "working directory"},
		{"./", "working directory"},
		{"*", "working directory"},
		{"*/", "working directory"},
		{"**", "working directory"},
		{"**/", "working directory"},
		{"$CI_PROJECT_DIR", "working directory"},
		{"$CI_PROJECT_DIR/", "working directory"},
		{"${CI_PROJECT_DIR}", "working directory"},
		{"${CI_PROJECT_DIR}/", "working directory"},
		{".git", ".git"},
		{".git/", ".git"},
		{".git/config", ".git"},
		{"./.git/", ".git"},
		{"foo/.git/**", ".git"},
		{"**/.git/**", ".git"},
		{"foo/.git/.git/config", ".git"},
		{"dist/", ""},
		{"dist/*", ""},
		{"dist/**", ""},
		{"$CI_PROJECT_DIR/dist/", ""},
		{"${CI_PROJECT_DIR}/dist/", ""},
		{"$CI_PROJECT_DIRECTORY", ""},
		{".github/", ""},
		{".gitlab/", ""},
		{".gitignore", ""},
		{".gitmodules", ""},
		{"foo/.github/", ""},
		{"foo/.gitlab/", ""},
		{"foo/.gitignore", ""},
		{"foo/.git-backup/", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f := findings005(t, fmt.Sprintf(`build:
  script: [make]
  artifacts:
    paths:
      - %q
    expire_in: 1 day
`, tc.path))
			if tc.risk == "" {
				if len(f) != 0 {
					t.Fatalf("expected no findings for a narrow or unrelated path, got %v", f)
				}
				return
			}
			if len(f) != 1 {
				t.Fatalf("expected one finding per offending path, got %v", f)
			}
			if f[0].RuleID != "GL005" || f[0].Severity != finding.Error || f[0].Job != "build" {
				t.Errorf("expected a GL005 error attributed to build, got %+v", f[0])
			}
			if f[0].File != "test.yml" || f[0].Line != 5 || f[0].Col != 9 {
				t.Errorf("expected the artifact path's source location, got %+v", f[0])
			}
			if !strings.Contains(f[0].Message, tc.risk) {
				t.Errorf("expected message to explain %q exposure, got %q", tc.risk, f[0].Message)
			}
		})
	}
}

func TestGL005_BroadArtifactExclusionsNoFinding(t *testing.T) {
	f := findings005(t, `build:
  script: [make]
  artifacts:
    paths: [dist/]
    exclude: ['.', './', '*', '**', '$CI_PROJECT_DIR', '${CI_PROJECT_DIR}/', '.git/', 'foo/.git/**']
    expire_in: 1 day
`)
	if len(f) != 0 {
		t.Fatalf("excluding broad paths or .git must not be treated as uploading them, got %v", f)
	}
}

func TestGL005_BroadArtifactsKeepExpiryFinding(t *testing.T) {
	f := findings005(t, `build:
  script: [make]
  artifacts:
    paths:
      - ./
      - .git/
test:
  script: [make test]
  artifacts:
    paths: [coverage.xml]
    expire_in: 1 day
`)
	if len(f) != 3 {
		t.Fatalf("expected two path errors and the existing expiry warning, got %v", f)
	}
	for i, wantLine := range []int{5, 6} {
		if f[i].Severity != finding.Error || f[i].Line != wantLine || f[i].Job != "build" {
			t.Errorf("expected an error on build's line %d, got %+v", wantLine, f[i])
		}
	}
	if f[2].Severity != finding.Warn || f[2].Job != "build" || !strings.Contains(f[2].Message, "expire_in") {
		t.Errorf("expected the existing expiry warning for build, got %+v", f[2])
	}
}

func TestGL005_BroadArtifactsInDefaultsAndTemplates(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		job  string
	}{
		{"default", `default:
  artifacts:
    paths: ['./']
    expire_in: 1 day
build:
  script: [make]
test:
  script: [make test]
`, ""},
		{"template", `.build:
  artifacts:
    paths: ['.git/']
    expire_in: 1 day
build:
  extends: .build
  script: [make]
test:
  extends: .build
  script: [make test]
`, ".build"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings005(t, tc.src)
			if len(f) != 1 {
				t.Fatalf("expected one path finding where written, got %v", f)
			}
			if f[0].Severity != finding.Error || f[0].Line != 3 || f[0].Job != tc.job {
				t.Errorf("expected error at line 3 attributed to %q, got %+v", tc.job, f[0])
			}
		})
	}
}

func TestGL005_ExistingPathFindingsUnchanged(t *testing.T) {
	for _, tc := range []struct {
		path    string
		message string
	}{
		{"/tmp/.git", `artifact path "/tmp/.git" is an absolute path — references the host filesystem directly and can exfiltrate arbitrary files on shell executors`},
		{"../.git", `artifact path "../.git" contains path traversal — can escape the project directory on shell executors`},
		{".git/credentials", `artifact path ".git/credentials" matches sensitive file pattern "*credential*" — exclude secrets from artifacts`},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f := findings005(t, fmt.Sprintf("build:\n  script: [make]\n  artifacts:\n    paths: [%q]\n    expire_in: 1 day\n", tc.path))
			if len(f) != 1 || f[0].Severity != finding.Error || f[0].Message != tc.message {
				t.Errorf("expected the existing single path finding %q, got %v", tc.message, f)
			}
		})
	}
}

// Git LFS's logs under .git hold no history or configuration (#999).
func TestGL005_GitLFSLogs(t *testing.T) {
	for path, want := range map[string]int{
		"source/.git/lfs/logs/": 0,
		".git/lfs/logs/*.log":   0,
		".git/":                 1,
		"source/.git/config":    1,
		".git/lfs/objects/":     1,
	} {
		doc, err := parser.Parse([]byte("build:\n  script: [make]\n  artifacts:\n    paths:\n      - '"+path+"'\n    expire_in: 1 day\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL005.Check(doc.Root, "test.yml")); got != want {
			t.Errorf("%s: got %d findings, want %d", path, got, want)
		}
	}
}

func TestGitLogOnlyPath_NoGitDir(t *testing.T) {
	if gitLogOnlyPath("build/lfs/logs/") {
		t.Error("a path outside .git is not a .git log path")
	}
}

// Package manager and registry config files hold auth tokens (#1133).
func TestGL005_CredentialConfigFiles(t *testing.T) {
	for _, tc := range []struct {
		path    string
		pattern string // "" means no finding
	}{
		{".npmrc", ".npmrc"},
		{"frontend/.npmrc", ".npmrc"},
		{".yarnrc.yml", ".yarnrc.yml"},
		{".pypirc", ".pypirc"},
		{".netrc", ".netrc"},
		{"_netrc", "_netrc"},
		{".dockercfg", ".dockercfg"},
		{".docker/config.json", ".docker/config.json"},
		{"./.docker/config.json", ".docker/config.json"},
		{"home/.docker/config.json", ".docker/config.json"},
		{".Docker/Config.json", ".docker/config.json"},
		// A bare config.json is usually an app config.
		{"config.json", ""},
		{"dist/config.json", ""},
		{"x.docker/config.json", ""},
		{".docker/", ""},
		{".npmrc.example.txt", ""},
		{".yarnrc", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f := findings005(t, fmt.Sprintf("build:\n  script: [make]\n  artifacts:\n    paths: [%q]\n    expire_in: 1 day\n", tc.path))
			if tc.pattern == "" {
				if len(f) != 0 {
					t.Errorf("expected no finding, got %v", f)
				}
				return
			}
			want := fmt.Sprintf("artifact path %q matches sensitive file pattern %q — exclude secrets from artifacts", tc.path, tc.pattern)
			if len(f) != 1 || f[0].Severity != finding.Error || f[0].Message != want || f[0].Line != 4 {
				t.Errorf("expected one error %q on line 4, got %v", want, f)
			}
		})
	}
}

// A credential file listed under exclude: is the fix, not the problem.
func TestGL005_CredentialConfigFilesExcluded(t *testing.T) {
	f := findings005(t, `
build:
  script: [make]
  artifacts:
    paths: [dist/]
    exclude: [.npmrc, .docker/config.json]
    expire_in: 1 day
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for excluded credential files, got %v", f)
	}
}

// An .npmrc or .yarnrc.yml the job writes with an unexpanded placeholder holds
// no token: npm and Yarn resolve ${VAR} when they read the file (#1171).
func TestGL005_PlaceholderRCFile(t *testing.T) {
	for _, tc := range []struct {
		name, script, path string
		flagged            bool
	}{
		{"escaped dollar", `echo "${NPM_PROJECT_LEVEL_ENDPOINT}:_authToken=\${CI_JOB_TOKEN}" >> .npmrc`, ".npmrc", false},
		{"single quoted", `echo '//registry.npmjs.org/:_authToken=${NPM_TOKEN}' > .npmrc`, ".npmrc", false},
		{"printf single quoted", `printf '%s\n' '//r/:_authToken=${NPM_TOKEN}' > ./.npmrc`, ".npmrc", false},
		{"project dir prefix", `echo '//r/:_authToken=${NPM_TOKEN}' > "$CI_PROJECT_DIR/.npmrc"`, ".npmrc", false},
		{"tee", `echo '//r/:_authToken=${NPM_TOKEN}' | tee -a .npmrc`, ".npmrc", false},
		{"yarnrc", `echo 'npmAuthToken: "${NPM_TOKEN}"' > .yarnrc.yml`, ".yarnrc.yml", false},
		{"group", `{ echo '@s:registry=https://r/'; echo '//r/:_authToken=${NPM_TOKEN}'; } > .npmrc`, ".npmrc", false},
		{"quoted heredoc", "cat > .npmrc <<'EOF'\n//r/:_authToken=${NPM_TOKEN}\nEOF", ".npmrc", false},
		{"double quoted", `echo "//r/:_authToken=${NPM_TOKEN}" > .npmrc`, ".npmrc", true},
		{"unquoted", `echo //r/:_authToken=$NPM_TOKEN > .npmrc`, ".npmrc", true},
		{"single quote inside double", `echo "it's ${NPM_TOKEN}" > .npmrc`, ".npmrc", true},
		{"group with expanded secret", `{ echo '@s:registry=https://r/'; echo "//r/:_authToken=${NPM_TOKEN}"; } >> .npmrc`, ".npmrc", true},
		{"subshell with expanded secret", `(echo a; echo "//r/:_authToken=$NPM_TOKEN") > .npmrc`, ".npmrc", true},
		{"unquoted heredoc", "cat > .npmrc <<EOF\n//r/:_authToken=${NPM_TOKEN}\nEOF", ".npmrc", true},
		{"unquoted heredoc single quotes", "cat > .npmrc <<EOF\n//r/:_authToken='${NPM_TOKEN}'\nEOF", ".npmrc", true},
		{"command substitution", `echo "//r/:_authToken=$(cat token)" > .npmrc`, ".npmrc", true},
		{"envsubst", `envsubst < npmrc.tpl > .npmrc`, ".npmrc", true},
		{"copied", `cp "$NPMRC" .npmrc`, ".npmrc", true},
		{"npm config set", `npm config set --location project //r/:_authToken "$NPM_TOKEN"`, ".npmrc", true},
		{"not written", `npm ci`, ".npmrc", true},
		{"other directory", `cd pkg && echo '//r/:_authToken=${NPM_TOKEN}' > .npmrc`, ".npmrc", true},
		{"pypirc", `echo 'password = ${PYPI_TOKEN}' > .pypirc`, ".pypirc", true},
		{"netrc", `echo 'password ${NETRC_PASSWORD}' > .netrc`, ".netrc", true},
		{"subshell with secret before the last command", `(echo "//r/:_authToken=$NPM_TOKEN"; echo b) > .npmrc`, ".npmrc", true},
		{"group with secret before the last command", `{ echo "//r/:_authToken=$NPM_TOKEN"; echo b; } > .npmrc`, ".npmrc", true},
		{"credential key, any name", `echo "//r/:_authToken=$TOKEN" > .npmrc`, ".npmrc", true},
		{"credential key, braced", `echo "//r/:_auth=${NEXUS_CREDS}" > .npmrc`, ".npmrc", true},
		{"credential key, password", `echo "//r/:_password=$PASS" >> .npmrc`, ".npmrc", true},
		{"credential key, copied variable", `T=$NPM_TOKEN; echo "//r/:_authToken=$T" > .npmrc`, ".npmrc", true},
		{"yarn credential key", `echo "npmAuthToken: $GITLAB_PAT" > .yarnrc.yml`, ".yarnrc.yml", true},
		{"yarn ident key", `echo "npmAuthIdent: ${CREDS}" > .yarnrc.yml`, ".yarnrc.yml", true},
		{"endpoint before the key", `echo "${NPM_PROJECT_LEVEL_ENDPOINT}:_authToken=\${TOKEN}" > .npmrc`, ".npmrc", false},
		{"npm config set after a flag value", `npm --location project config set //r/:_authToken x`, ".npmrc", true},
		{"yarn npm login", `yarn npm login --scope s`, ".npmrc", true},
		{"file test and touch", "if [[ ! -f .npmrc ]]; then\n  touch .npmrc\nfi\necho '//r/:_authToken=${NPM_TOKEN}' >> .npmrc", ".npmrc", false},
		{"test command", `test -f .npmrc || echo '//r/:_authToken=${NPM_TOKEN}' > .npmrc`, ".npmrc", false},
		{"touch only", `touch .npmrc`, ".npmrc", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings005(t, fmt.Sprintf("build:\n  script:\n    - %q\n  artifacts:\n    paths: [%q]\n    expire_in: 1 day\n", tc.script, tc.path))
			if got := len(f) == 1; got != tc.flagged || len(f) > 1 {
				t.Errorf("flagged = %v, want %v: %v", got, tc.flagged, f)
			}
		})
	}
}

// One expanded write is enough, even next to a placeholder write.
func TestGL005_PlaceholderRCFileMixed(t *testing.T) {
	f := findings005(t, `
build:
  script:
    - echo "@s:registry=https://r/" > .npmrc
    - echo '//r/:_authToken=${CI_JOB_TOKEN}' >> .npmrc
    - echo "//other/:_authToken=${NPM_TOKEN}" >> .npmrc
  artifacts:
    paths: [.npmrc]
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Errorf("expected one finding, got %v", f)
	}
}

// The exception reads the job's own script only: a file written by another
// job, or an artifacts block under default:, is reported.
func TestGL005_PlaceholderRCFileOtherJob(t *testing.T) {
	f := findings005(t, `
default:
  artifacts:
    paths: [.npmrc]
    expire_in: 1 day
write:
  script:
    - echo '//r/:_authToken=${NPM_TOKEN}' > .npmrc
upload:
  script: [ls]
  artifacts:
    paths: [.npmrc]
    expire_in: 1 day
`)
	if len(f) != 2 {
		t.Errorf("expected findings for default: and upload, got %v", f)
	}
}

// A template's paths are exempt only when every job that extends it writes
// the file with a placeholder.
func TestGL005_PlaceholderRCFileTemplate(t *testing.T) {
	const tmpl = `
.publish:
  artifacts:
    paths: [.npmrc]
    expire_in: 1 day
a:
  extends: .publish
  script:
    - echo '//r/:_authToken=${NPM_TOKEN}' > .npmrc
`
	if f := findings005(t, tmpl); len(f) != 0 {
		t.Errorf("expected no finding, got %v", f)
	}
	f := findings005(t, tmpl+`b:
  extends: .publish
  script:
    - echo "//r/:_authToken=${NPM_TOKEN}" > .npmrc
`)
	if len(f) != 1 || f[0].Job != ".publish" {
		t.Errorf("expected one finding on .publish, got %v", f)
	}
	// An unused template is reported where it is written.
	f = findings005(t, `
.publish:
  script:
    - echo '//r/:_authToken=${NPM_TOKEN}' > .npmrc
  artifacts:
    paths: [.npmrc]
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Errorf("expected one finding on the unused template, got %v", f)
	}
}

// The snippet from GitLab's npm documentation: a multi-line group appending
// placeholder lines (#1171).
func TestGL005_PlaceholderRCFileDocsSnippet(t *testing.T) {
	f := findings005(t, `
create_npmrc:
  script:
    - |
      {
        echo "@${CI_PROJECT_ROOT_NAMESPACE}:registry=${NPM_PACKAGE_REGISTRY}"
        echo "${NPM_PROJECT_LEVEL_ENDPOINT}:_authToken=\${CI_JOB_TOKEN}"
      } >> .npmrc
  artifacts:
    paths:
      - .npmrc
    expire_in: 1 day
`)
	if len(f) != 0 {
		t.Errorf("expected no finding, got %v", f)
	}
}

// A pipe inside "$(…)" splits the command before its redirect. The second
// write must not go unseen because the first one is a placeholder.
func TestGL005_PlaceholderRCFileSubstitutionWithPipe(t *testing.T) {
	f := findings005(t, `
build:
  script:
    - echo '@s:registry=https://r/' > .npmrc
    - echo "_auth=$(echo -n "$NPM_USER:$NPM_PASS" | base64)" >> .npmrc
  artifacts:
    paths: [.npmrc]
    expire_in: 1 day
`)
	if len(f) != 1 {
		t.Errorf("expected one finding, got %v", f)
	}
}
