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

func findings002(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL002.Check(doc.Root, "test.yml")
}

func TestGL002_UnquotedRefName(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - ./run.sh $CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity")
	}
}

func TestGL002_QuotedRefName(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo "$CI_COMMIT_REF_NAME"
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for double-quoted variable, got %d", len(f))
	}
}

func TestGL002_QuotedMidString(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo "Branch: $CI_COMMIT_REF_NAME"
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for variable inside double-quoted string, got %d", len(f))
	}
}

func TestGL002_MultipleQuotedVars(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo "$CI_COMMIT_REF_NAME and $CI_COMMIT_MESSAGE"
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for multiple vars inside double-quoted string, got %d", len(f))
	}
}

func TestGL002_SingleQuoted(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo '$CI_COMMIT_REF_NAME'
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for single-quoted variable, got %d", len(f))
	}
}

func TestGL002_EscapedDollar(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo \$CI_COMMIT_REF_NAME
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for escaped dollar, got %d", len(f))
	}
}

func TestGL002_BraceForm(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo ${CI_COMMIT_REF_NAME}
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for brace form, got %d", len(f))
	}
}

func TestGL002_MultipleVars(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo $CI_COMMIT_TITLE
    - ./deploy.sh $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestGL002_CommitBranch(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - git checkout $CI_COMMIT_BRANCH
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_BRANCH, got %d", len(f))
	}
}

func TestGL002_CommitTag(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - git tag -a $CI_COMMIT_TAG -m release
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_TAG, got %d", len(f))
	}
}

func TestGL002_CommitTagMessage(t *testing.T) {
	f := findings002(t, `
release:
  script:
    - echo Releasing $CI_COMMIT_TAG_MESSAGE
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_TAG_MESSAGE, got %d", len(f))
	}
}

func TestGL002_PipelineName(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - ./trigger.sh $CI_PIPELINE_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_PIPELINE_NAME, got %d", len(f))
	}
}

func TestGL002_CommitAuthor(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo hi $CI_COMMIT_AUTHOR
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_COMMIT_AUTHOR, got %d", len(f))
	}
}

func TestGL002_GitlabUserName(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - ./greet.sh $GITLAB_USER_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for GITLAB_USER_NAME, got %d", len(f))
	}
}

func TestGL002_GitlabUserEmail(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - ./mail.sh $GITLAB_USER_EMAIL
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for GITLAB_USER_EMAIL, got %d", len(f))
	}
}

func TestGL002_GitlabUserLoginNotFlagged(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo $GITLAB_USER_LOGIN
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for GITLAB_USER_LOGIN (restricted charset), got %d", len(f))
	}
}

func TestGL002_SafeVariable(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo $CI_JOB_ID
    - echo $CI_PROJECT_NAME
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for non-user-controlled variables, got %d", len(f))
	}
}

func TestGL002_BeforeScript(t *testing.T) {
	f := findings002(t, `
build:
  before_script:
    - git checkout $CI_COMMIT_REF_NAME
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in before_script, got %d", len(f))
	}
}

func TestGL002_TopLevelBeforeScript(t *testing.T) {
	f := findings002(t, `
before_script:
  - echo $CI_COMMIT_MESSAGE

build:
  script:
    - make
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in top-level before_script, got %d", len(f))
	}
}

func TestGL002_LineNumbers(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - ./run.sh $CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL002_SubshellInjection(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - make test BRANCH=$CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for assignment context, got %d", len(f))
	}
}

func TestGL002_DeduplicatePerLine(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo $CI_COMMIT_REF_NAME $CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding (deduplicated), got %d", len(f))
	}
}

func TestGL002_NoSuffixMatch(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo $CI_COMMIT_REF_NAME_CUSTOM
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for suffixed variable name, got %d", len(f))
	}
}

func TestGL002_BareAssignment(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - BRANCH=$CI_COMMIT_REF_NAME
    - git checkout "$BRANCH"
`)
	if len(f) != 0 {
		t.Errorf("expected no findings for bare assignment RHS, got %d", len(f))
	}
}

func TestGL002_BareAssignmentThenUnquotedUse(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - BRANCH=$CI_COMMIT_REF_NAME
    - git checkout $CI_COMMIT_REF_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for unquoted use, got %d", len(f))
	}
}

func TestGL002_ExternalPullRequestSourceBranch_Warn(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo building $CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME, got %d", len(f))
	}
}

// The rest of the external-pull-request family is not attacker-controlled in a
// way that reaches a shell: the target branch belongs to the mirroring project,
// the SHAs are hex, and the IID is numeric.
func TestGL002_OtherExternalPullRequestVars_NoFinding(t *testing.T) {
	for _, v := range []string{
		"CI_EXTERNAL_PULL_REQUEST_IID",
		"CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA",
		"CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_NAME",
		"CI_EXTERNAL_PULL_REQUEST_TARGET_BRANCH_SHA",
	} {
		f := findings002(t, "build:\n  script:\n    - echo $"+v+"\n")
		if len(f) != 0 {
			t.Errorf("expected no finding for %s, got %d", v, len(f))
		}
	}
}

// The \b anchor must not let the source-branch entry match its own SHA sibling.
func TestGL002_ExternalPullRequestPrefixNotMatched(t *testing.T) {
	f := findings002(t, `
build:
  script:
    - echo $CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA
`)
	if len(f) != 0 {
		t.Errorf("expected no finding for the SHA variant, got %d", len(f))
	}
}

// --- variables expanded into code (eval, sh -c, interpreter -c/-e) ---

func TestGL002_EvaluatedQuotedArg(t *testing.T) {
	cases := map[string]string{
		`eval "echo building $CI_MERGE_REQUEST_TITLE"`:        "`eval`",
		`bash -c "echo $CI_COMMIT_MESSAGE"`:                   "`bash -c`",
		`sh -c "git checkout $CI_COMMIT_BRANCH"`:              "`sh -c`",
		`bash -ec "make deploy BRANCH=${CI_COMMIT_REF_NAME}"`: "`bash -ec`",
		`sh -e -c "echo $CI_COMMIT_TITLE"`:                    "`sh -e -c`",
		`python3 -c "print('$CI_COMMIT_BRANCH')"`:             "`python3 -c`",
		`node -e "console.log('$CI_MERGE_REQUEST_TITLE')"`:    "`node -e`",
		`perl -e "print qq($CI_COMMIT_MESSAGE)"`:              "`perl -e`",
		`docker run alpine sh -c "echo $CI_COMMIT_REF_NAME"`:  "`sh -c`",
		`/bin/sh -c "echo $CI_COMMIT_MESSAGE"`:                "`sh -c`",
		`docker run img /bin/bash -c "deploy $CI_COMMIT_TAG"`: "`bash -c`",
		`test -n "$X" && eval "notify $GITLAB_USER_NAME"`:     "`eval`",
	}
	for line, cmd := range cases {
		f := findings002(t, "job:\n  script:\n    - '"+strings.ReplaceAll(line, "'", "''")+"'\n")
		if len(f) != 1 {
			t.Errorf("%s: expected 1 finding, got %d", line, len(f))
			continue
		}
		if !strings.Contains(f[0].Message, "evaluated by "+cmd) {
			t.Errorf("%s: expected message naming %s, got %q", line, cmd, f[0].Message)
		}
	}
}

func TestGL002_EvaluatedQuotedArg_NoFinding(t *testing.T) {
	for _, line := range []string{
		`echo "$CI_COMMIT_MESSAGE"`,
		`./finish -c "$CI_COMMIT_MESSAGE"`,
		`git checkout "$CI_COMMIT_BRANCH"`,
		`eval "$(ssh-agent -s)"`,
		`bash -c "make build"`,
		`bash -c 'echo done' "$CI_COMMIT_MESSAGE"`,
		`eval "echo \$CI_COMMIT_MESSAGE"`,
		`echo "remember to eval \"$CI_COMMIT_TITLE\" later"`,
		`python3 -c "import sys; print(sys.argv[1])" "$CI_COMMIT_BRANCH"`,
	} {
		f := findings002(t, "job:\n  script:\n    - '"+strings.ReplaceAll(line, "'", "''")+"'\n")
		if len(f) != 0 {
			t.Errorf("%s: expected no finding, got %q", line, f[0].Message)
		}
	}
}

func TestGL002_EvalUnquotedKeepsOriginalFinding(t *testing.T) {
	f := findings002(t, `
job:
  script:
    - eval echo $CI_COMMIT_MESSAGE
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "unquoted user-controlled variable") {
		t.Errorf("expected the unquoted-variable message, got %q", f[0].Message)
	}
}

func TestGL002_EvaluatedAndUnquotedSameVar_OneFinding(t *testing.T) {
	f := findings002(t, `
job:
  script:
    - bash -c "echo $CI_COMMIT_BRANCH" && echo $CI_COMMIT_BRANCH
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for one variable, got %d", len(f))
	}
}

func TestGL002_EvaluatedArgInBlockScalar_DoesNotCrossLines(t *testing.T) {
	f := findings002(t, `
job:
  script:
    - |
      bash -c
      echo "$CI_COMMIT_MESSAGE"
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding when -c and the quoted string are on different lines, got %d", len(f))
	}
}

func TestGL002_NewUserControlledVars(t *testing.T) {
	for _, v := range []string{"CI_CONFIG_REF_URI", "CI_RELEASE_DESCRIPTION", "AI_FLOW_INPUT", "AI_FLOW_CONTEXT"} {
		f := findings002(t, "job:\n  script:\n    - echo $"+v+"\n    - echo ${"+v+"}\n")
		if len(f) != 2 {
			t.Errorf("%s: expected 2 findings for unquoted use, got %d", v, len(f))
		}
		if f := findings002(t, "job:\n  script:\n    - echo \"$"+v+"\"\n"); len(f) != 0 {
			t.Errorf("%s: expected no finding when quoted, got %d", v, len(f))
		}
	}
	for _, v := range []string{"AI_FLOW_EVENT", "AI_FLOW_GOAL", "CI_COMMIT_USER_LOGIN", "CI_PROJECT_TOPICS"} {
		if f := findings002(t, "job:\n  script:\n    - echo $"+v+"\n"); len(f) != 0 {
			t.Errorf("%s: not user-controlled, expected no finding, got %d", v, len(f))
		}
	}
}

func TestGL002_NoWordSplitting(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{`export VERSION=$CI_COMMIT_TAG`, 0},
		{`export VERSION=${CI_COMMIT_TAG##v}`, 0},
		{`local ref=$CI_COMMIT_REF_NAME`, 0},
		{`declare -r REF=$CI_COMMIT_REF_NAME`, 0},
		{`A=1 IMAGE_TAG=$CI_COMMIT_REF_NAME ./build.sh`, 0},
		{`cd app && IMAGE_TAG=$CI_COMMIT_REF_NAME`, 0},
		{`if [[ $CI_COMMIT_TAG =~ dev ]]; then echo dev; fi`, 0},
		{`case $CI_COMMIT_REF_NAME in main) echo m;; esac`, 0},
		{`if [ ! -z ${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME+x} ]; then echo mr; fi`, 0},
		{`[ -n "${CI_COMMIT_TAG:+set}" ]`, 0},
		{`curl --data "$(jq -n --arg tag "$CI_COMMIT_TAG" '{tag: $tag}')" https://example.com`, 0},
		{`make VERSION=$CI_COMMIT_TAG`, 1},
		{`echo $CI_COMMIT_REF_NAME`, 1},
		{`[[ -n x ]] && echo $CI_COMMIT_TAG`, 1},
		{`echo "$(git log $CI_COMMIT_REF_NAME)"`, 1},
		{`[ ${CI_COMMIT_TAG:-none} = none ]`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - "+strconv.Quote(tc.script)+"\n"), "t.yml")
		if err != nil {
			t.Fatal(err)
		}
		if f := GL002.Check(doc.Root, "t.yml"); len(f) != tc.want {
			t.Errorf("%s: expected %d findings, got %d", tc.script, tc.want, len(f))
		}
	}
}

func TestGL002_BlockLineAndMessage(t *testing.T) {
	doc, err := parser.Parse([]byte(`
job:
  script:
    - |
      echo start
      git push origin $CI_COMMIT_REF_NAME
      echo $GITLAB_USER_EMAIL
`), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := GL002.Check(doc.Root, "t.yml")
	if len(f) != 2 || f[0].Line != 6 || f[1].Line != 7 {
		t.Fatalf("expected findings on lines 6 and 7, got %v", f)
	}
	if !strings.Contains(f[1].Message, "user who started the pipeline") {
		t.Errorf("unexpected message: %s", f[1].Message)
	}
}

// A ${VAR} earlier on the line doesn't hide the [[ … ]] or the assignment
// the reference is in (#976).
func TestGL002_BracedVariableBefore(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{`[[ ${VERSION} == ${CI_COMMIT_TAG} ]]`, 0},
		{`export NAME=${PREFIX}-${CI_COMMIT_TAG}`, 0},
		{`NAME=${PREFIX:-x}-${CI_COMMIT_TAG} make`, 0},
		{`echo ${PREFIX} ${CI_COMMIT_TAG}`, 1},
		{`{ echo start; } ; echo ${CI_COMMIT_TAG}`, 1},
		{`{ X=1; } && echo ${CI_COMMIT_TAG}`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - '"+tc.line+"'\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL002.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.line, got, tc.want)
		}
	}
}

// commandStart stops at a { that opens a group, not one of ${, and at a }
// that closes a group (#976).
func TestCommandStart_Braces(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want int
	}{
		{"{ echo $X", 1},
		{"x{ echo $X", 2},
		{"}echo $X", 1},
		{"a; } echo $X", 4},
		{"echo ${A}b $X", 0},
	} {
		if got := commandStart(tc.s, strings.LastIndex(tc.s, "$X")); got != tc.want {
			t.Errorf("commandStart(%q) = %d, want %d", tc.s, got, tc.want)
		}
	}
}

// A here-document body is data: $VAR is expanded but not split, globbed or
// parsed, unless the body goes to a shell or interpreter (#1053).
func TestGL002_HeredocBodies(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         int
	}{
		{"cat to file", "cat > notes.md <<EOF\nRelease $CI_COMMIT_TAG\nEOF", 0},
		{"quoted delimiter", "cat <<'EOF' > notes.md\nRelease $CI_COMMIT_TAG\nEOF", 0},
		{"indented with <<-", "cat <<-END\n\tBuilt from $CI_COMMIT_REF_NAME\n\tEND", 0},
		{"apostrophe in body", "cat > n.md <<EOF\nit's $CI_COMMIT_TAG\nEOF\necho $CI_COMMIT_TITLE", 1},
		{"after the body", "cat > n.md <<EOF\nx\nEOF\necho $CI_COMMIT_TAG", 1},
		{"two heredocs on a line", "paste - - <<A 3<<B\n$CI_COMMIT_TAG\nA\n$CI_COMMIT_BRANCH\nB\necho $CI_COMMIT_TITLE", 1},
		{"sh reads the body", "sh <<EOF\necho $CI_COMMIT_TITLE\nEOF", 1},
		{"ssh runs the body", "ssh deploy@host <<EOF\ncd /srv && ./deploy $CI_COMMIT_TAG\nEOF", 1},
		{"su runs a login shell", "su -l packager <<EOS\ntar -cf x-${CI_COMMIT_TAG}.tar src\nEOS", 1},
		{"piped to bash", "cat <<EOF | bash\necho $CI_COMMIT_TITLE\nEOF", 1},
		{"<< inside quotes", "echo \"a << b\"\necho $CI_COMMIT_TAG", 1},
		{"here-string", "cat <<< $CI_COMMIT_TAG", 1},
		{"unterminated", "cat <<EOF\n$CI_COMMIT_TAG", 0},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - |\n      "+strings.ReplaceAll(tc.script, "\n", "\n      ")+"\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL002.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.name, got, tc.want)
		}
	}
}
