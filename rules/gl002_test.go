package rules

import (
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
