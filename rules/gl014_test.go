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

func findings014(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL014.Check(doc.Root, "test.yml")
}

func TestGL014_EnvDumpWithDotenv(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - make build
    - env > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL014_PrintenvDumpWithDotenv(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - printenv > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for printenv >, got %d", len(f))
	}
}

func TestGL014_EnvDumpNoDotenv_NoFinding(t *testing.T) {
	// env > file without dotenv artifact is not our concern
	f := findings014(t, `
build:
  script:
    - env > build.env
    - make build
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when no dotenv artifact, got %d", len(f))
	}
}

func TestGL014_DotenvNoEnvDump_NoFinding(t *testing.T) {
	// dotenv artifact with specific vars is safe
	f := findings014(t, `
build:
  script:
    - echo "BUILD_VERSION=$BUILD_VERSION" > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for specific var export, got %d", len(f))
	}
}

func TestGL014_BeforeScript(t *testing.T) {
	f := findings014(t, `
build:
  before_script:
    - env > vars.env
  script:
    - make
  artifacts:
    reports:
      dotenv: vars.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for env dump in before_script, got %d", len(f))
	}
}

func TestGL014_OneFindingPerJob(t *testing.T) {
	// Both script lines match but only one finding should be emitted per job
	f := findings014(t, `
build:
  script:
    - env > build.env
    - printenv > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding per job, got %d", len(f))
	}
}

func TestGL014_MultipleJobs(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - env > build.env
  artifacts:
    reports:
      dotenv: build.env

test:
  script:
    - env > test.env
  artifacts:
    reports:
      dotenv: test.env
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings for two jobs, got %d", len(f))
	}
}

func TestGL014_LineNumber(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - make build
    - env > build.env
  artifacts:
    reports:
      dotenv: build.env
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL014_DumpIntoArtifact(t *testing.T) {
	cases := map[string]struct{ script, artifacts string }{
		"env, file in paths":             {"env > diagnostics.txt", "paths: [diagnostics.txt]"},
		"printenv append":                {"printenv >> logs/env.txt", "paths: [logs/]"},
		"export -p":                      {"export -p > vars.sh", "paths: [\"*.sh\"]"},
		"proc environ":                   {"cat /proc/self/environ > environ.bin", "paths: [environ.bin]"},
		"tee":                            {"env | tee out/env.log", "paths: [out]"},
		"tee append":                     {"printenv | tee -a out/env.log", "paths: [\"out/*.log\"]"},
		"doublestar":                     {"env > reports/ci/env.txt", "paths: [\"**/*.txt\"]"},
		"whole directory":                {"env > env.txt", "paths: [.]"},
		"dot slash":                      {"env > ./env.txt", "paths: [\"./env.txt\"]"},
		"project dir variable":           {"env > $CI_PROJECT_DIR/env.txt", "paths: [env.txt]"},
		"untracked":                      {"env > env.txt", "untracked: true"},
		"untracked, unknown file":        {"env > $OUT_FILE", "untracked: true"},
		"after another command":          {"make build && env > env.txt", "paths: [env.txt]"},
		"quoted target":                  {`env > "env.txt"`, "paths: [env.txt]"},
		"glob directory component":       {"env > build-1/env.txt", "paths: [\"build-*\"]"},
		"bare set":                       {"set > vars.txt", "paths: [vars.txt]"},
		"bare export":                    {"export > exports.txt", "paths: [exports.txt]"},
		"declare -p":                     {"declare -p > vars.env", "paths: [vars.env]"},
		"declare -x append":              {"declare -x >> vars2.txt", "paths: [vars2.txt]"},
		"typeset -x":                     {"typeset -x > typeset.txt", "paths: [typeset.txt]"},
		"env -0":                         {"env -0 > env.bin", "paths: [env.bin]"},
		"powershell gci":                 {"gci env: > env.txt", "paths: [env.txt]"},
		"powershell Get-ChildItem":       {"Get-ChildItem env: > env.txt", "paths: [env.txt]"},
		"powershell tee":                 {"Get-ChildItem env: | tee env.txt", "paths: [env.txt]"},
		"powershell Format-Table":        {"Get-ChildItem Env: | Format-Table > env.txt", "paths: [env.txt]"},
		"powershell Format-Table append": {"Get-ChildItem Env: | Format-Table >> env.txt", "paths: [env.txt]"},
		"powershell Format-Table tee":    {"Get-ChildItem Env: | Format-Table | tee env.txt", "paths: [env.txt]"},
		"powershell Format-Table tee -a": {"Get-ChildItem Env: | Format-Table | tee -a env.txt", "paths: [env.txt]"},
		"powershell Format-List":         {"Get-ChildItem Env: | Format-List > env.txt", "paths: [env.txt]"},
		"powershell Out-String":          {"Get-ChildItem Env: | Out-String > env.txt", "paths: [env.txt]"},
		"powershell format flags":        {"Get-ChildItem Env: | Format-Table -AutoSize > env.txt", "paths: [env.txt]"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings014(t, fmt.Sprintf(`
diag:
  script:
    - %q
  artifacts:
    %s
    expire_in: 1 day
`, tc.script, tc.artifacts))
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Severity != finding.Warn || !strings.Contains(f[0].Message, "artifacts upload") {
				t.Errorf("unexpected finding: %+v", f[0])
			}
		})
	}
}

func TestGL014_DumpNotInArtifact_NoFinding(t *testing.T) {
	cases := map[string]struct{ script, artifacts string }{
		"other file":              {"env > diagnostics.txt", "paths: [dist/]"},
		"excluded":                {"env > out/env.txt", "paths: [out/]\n    exclude: [\"out/*.txt\"]"},
		"excluded from untracked": {"env > env.txt", "untracked: true\n    exclude: [env.txt]"},
		"outside project":         {"env > /tmp/env.txt", "paths: [\"**\"]"},
		"variable target":         {"env > $OUT_FILE", "paths: [dist/]"},
		"single variable":         {"printenv HOME > home.txt", "paths: [home.txt]"},
		"filtered env":            {"env | grep ^APP_ > app.env", "paths: [app.env]"},
		"dotenv file contents":    {"cat .env > merged.env", "paths: [merged.env]"},
		"glob in one segment":     {"env > a/b/env.txt", "paths: [\"a/*.txt\"]"},
		"env runs a command":      {"env FOO=1 make > build.log", "paths: [build.log]"},
		"set -e":                  {"set -e > log.txt", "paths: [log.txt]"},
		"set -euo pipefail":       {"set -euo pipefail > log.txt", "paths: [log.txt]"},
		"set +x":                  {"set +x > log.txt", "paths: [log.txt]"},
		"export assignment":       {"export FOO=bar > log.txt", "paths: [log.txt]"},
		"export PATH":             {`export PATH="$PATH:/x" > log.txt`, "paths: [log.txt]"},
		"declare array":           {"declare -a arr=(1 2) > log.txt", "paths: [log.txt]"},
		"declare readonly":        {"declare -r foo=bar > log.txt", "paths: [log.txt]"},
		"declare one variable":    {"declare -p FOO > foo.txt", "paths: [foo.txt]"},
		"powershell one variable": {"Get-ChildItem env:PATH > path.txt", "paths: [path.txt]"},
		"powershell env variable": {"echo $env:PATH > path.txt", "paths: [path.txt]"},
		"powershell filtered":     {"Get-ChildItem env: | Select-String PATH > path.txt", "paths: [path.txt]"},
		// Text inside quotes is not a command, even with separators in it.
		"quoted set":    {`echo "hello; set > f"`, "paths: [f]"},
		"quoted export": {`echo 'hello; export > f'`, "paths: [f]"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := findings014(t, fmt.Sprintf(`
diag:
  script:
    - %q
  artifacts:
    %s
    expire_in: 1 day
`, tc.script, tc.artifacts))
			if len(f) != 0 {
				t.Fatalf("expected no finding, got %v", f)
			}
		})
	}
}

func TestGL014_DefaultArtifacts(t *testing.T) {
	f := findings014(t, `
default:
  artifacts:
    paths: [env.txt]
diag:
  script:
    - env > env.txt
`)
	if len(f) != 1 {
		t.Fatalf("expected the default: artifacts to apply, got %d findings", len(f))
	}
}

func TestGL014_DotenvMessageWins(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - env > build.env
  artifacts:
    paths: [build.env]
    reports:
      dotenv: build.env
`)
	if len(f) != 1 || !strings.Contains(f[0].Message, "dotenv") {
		t.Fatalf("expected one dotenv finding, got %v", f)
	}
}

// A dump after a case label writes the file like any other command (#1178).
func TestGL014_CaseArm(t *testing.T) {
	for arm, want := range map[string]int{
		"debug) env > vars.txt ;;":     1,
		"debug) set > vars.txt ;;":     1,
		"debug) export > vars.txt ;;":  1,
		"set|debug) set > vars.txt ;;": 1,
		"set) make > vars.txt ;;":      0,
		"debug) set -e > vars.txt ;;":  0,
	} {
		t.Run(arm, func(t *testing.T) {
			src := "build:\n  script:\n    - |\n      case \"$1\" in\n        " + arm + "\n      esac\n  artifacts:\n    paths: [vars.txt]\n"
			if f := findings014(t, src); len(f) != want {
				t.Fatalf("got %v, want %d findings", f, want)
			}
		})
	}
}

func TestGL014_PowerShellFileCmdlets(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{`gci env: | Out-File env.txt`, 1},
		{`gci env: | Out-File -FilePath env.txt`, 1},
		{`gci env: | Out-File -Append -FilePath env.txt`, 1},
		{`gci env: | Set-Content env.txt`, 1},
		{`gci env: | Set-Content -Path env.txt`, 1},
		{`gci env: | Add-Content env.txt`, 1},
		{`gci env: | Tee-Object env.txt`, 1},
		{`gci env: | Tee-Object -FilePath env.txt`, 1},
		{`gci env: | Format-List | Out-File env.txt`, 1},
		{`gci env: | Out-File other.txt`, 0},
		{`gci env: | Tee-Object -Variable env.txt`, 0},
		{`gci env: | Select-String PATH | Out-File env.txt`, 0},
	} {
		t.Run(tc.line, func(t *testing.T) {
			src := fmt.Sprintf("job:\n  script:\n    - %q\n  artifacts:\n    paths:\n      - env.txt\n", tc.line)
			if got := checkRule(t, GL014, src); len(got) != tc.want {
				t.Errorf("got %d findings, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

func TestGL014_SecretInDotenv(t *testing.T) {
	const report = "\n  artifacts:\n    reports:\n      dotenv: build.env\n"
	for _, tc := range []struct {
		name, line string
		want       int
	}{
		{"append", `echo "DEPLOY_TOKEN=$DEPLOY_TOKEN" >> build.env`, 1},
		{"overwrite", `echo "API_KEY=${API_KEY}" > build.env`, 1},
		{"other name", `echo "OUT=$DB_PASSWORD" >> build.env`, 1},
		{"unquoted", `echo DEPLOY_TOKEN=$DEPLOY_TOKEN >> build.env`, 1},
		{"printf", `printf "%s\n" "A=1" "DEPLOY_TOKEN=$DEPLOY_TOKEN" >> build.env`, 1},
		{"tee", `echo "DEPLOY_TOKEN=$DEPLOY_TOKEN" | tee -a build.env`, 1},
		{"relative", `echo "DEPLOY_TOKEN=$DEPLOY_TOKEN" >> ./build.env`, 1},
		{"project dir", `echo "DEPLOY_TOKEN=$DEPLOY_TOKEN" >> "$CI_PROJECT_DIR/build.env"`, 1},
		{"not secret", `echo "VERSION=$CI_COMMIT_TAG" >> build.env`, 0},
		{"secret id", `echo "KEY=$GPG_KEY_ID" >> build.env`, 0},
		{"single quotes", `echo 'DEPLOY_TOKEN=$DEPLOY_TOKEN' >> build.env`, 0},
		{"escaped", `echo "DEPLOY_TOKEN=\$DEPLOY_TOKEN" >> build.env`, 0},
		{"conditional", `echo "HAS_TOKEN=${DEPLOY_TOKEN:+yes}" >> build.env`, 0},
		{"substitution", `echo "SIG=$(./sign "$DEPLOY_TOKEN")" >> build.env`, 0},
		{"other file", `echo "DEPLOY_TOKEN=$DEPLOY_TOKEN" >> other.env`, 0},
		{"separate command", `echo "DEPLOY_TOKEN=$DEPLOY_TOKEN"; echo "A=1" >> build.env`, 0},
		{"not a print command", `curl -d "token=$DEPLOY_TOKEN" https://example.com > build.env`, 0},
		{"comment", `# echo "DEPLOY_TOKEN=$DEPLOY_TOKEN" >> build.env`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings014(t, fmt.Sprintf("build:\n  script:\n    - |\n      %s%s", tc.line, report))
			if len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %v", len(f), tc.want, f)
			}
		})
	}
}

func TestGL014_SecretInDotenvList(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - echo start
    - |
      echo one
      echo "DEPLOY_TOKEN=$DEPLOY_TOKEN" >> b.env
  artifacts:
    reports:
      dotenv: [a.env, b.env]
`)
	if len(f) != 1 || f[0].Line != 7 || !strings.Contains(f[0].Message, "DEPLOY_TOKEN") || !strings.Contains(f[0].Message, `"b.env"`) {
		t.Fatalf("got %+v", f)
	}
}

func TestGL014_SecretInFileWithoutDotenv(t *testing.T) {
	f := findings014(t, `
build:
  script:
    - echo "DEPLOY_TOKEN=$DEPLOY_TOKEN" >> build.env
  artifacts:
    paths: [dist/]
`)
	if len(f) != 0 {
		t.Fatalf("got %+v", f)
	}
}
