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

func findings020(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL020.Check(doc.Root, "test.yml")
}

func TestGL020_CurlOThenExecute(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - tar xzf tool.tar.gz
    - ./tool install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != finding.Warn {
		t.Errorf("expected Warn severity, got %s", f[0].Severity)
	}
}

func TestGL020_CurlOutputFlag(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSL -o tool.sh https://example.com/install.sh
    - bash tool.sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for -o flag, got %d", len(f))
	}
}

func TestGL020_WgetNoChecksum(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - wget https://example.com/tool.tar.gz
    - tar xzf tool.tar.gz
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for wget without checksum, got %d", len(f))
	}
}

func TestGL020_WithSha256sum_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - echo "abc123def456  tool.tar.gz" | sha256sum -c
    - tar xzf tool.tar.gz
    - ./tool install
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when sha256sum is present, got %d", len(f))
	}
}

func TestGL020_WithShasum_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - shasum -a 256 -c checksums.txt
    - tar xzf tool.tar.gz
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when shasum is present, got %d", len(f))
	}
}

func TestGL020_WithGpgVerify_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - curl -sSLO https://example.com/tool.tar.gz.sig
    - gpg --verify tool.tar.gz.sig tool.tar.gz
    - tar xzf tool.tar.gz
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when gpg --verify is present, got %d", len(f))
	}
}

func TestGL020_WithCosignVerify_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - cosign verify tool.tar.gz
    - tar xzf tool.tar.gz
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when cosign verify is present, got %d", len(f))
	}
}

func TestGL020_CurlPipeBash_NoFinding(t *testing.T) {
	// GL011 territory — direct pipe, not a save-then-execute pattern
	f := findings020(t, `
install:
  script:
    - curl -sSL https://example.com/install.sh | bash
`)
	if len(f) != 0 {
		t.Errorf("expected no GL020 finding for direct curl|bash (covered by GL011), got %d", len(f))
	}
}

func TestGL020_NoCurlWget_NoFinding(t *testing.T) {
	f := findings020(t, `
build:
  script:
    - go build ./...
    - tar xzf prebuilt.tar.gz
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when no curl/wget present, got %d", len(f))
	}
}

func TestGL020_ChecksumInBeforeScript_NoFinding(t *testing.T) {
	f := findings020(t, `
install:
  before_script:
    - curl -sSLO https://example.com/tool.tar.gz
    - sha256sum -c checksums.txt
  script:
    - ./tool install
`)
	if len(f) != 0 {
		t.Errorf("expected no finding when sha256sum is in before_script, got %d", len(f))
	}
}

func TestGL020_OneFindinPerJob(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool1.tar.gz
    - curl -sSLO https://example.com/tool2.tar.gz
    - tar xzf tool1.tar.gz && tar xzf tool2.tar.gz
`)
	if len(f) != 1 {
		t.Fatalf("expected exactly 1 finding per job (not per download), got %d", len(f))
	}
}

func TestGL020_LineNumber(t *testing.T) {
	f := findings020(t, `
install:
  script:
    - curl -sSLO https://example.com/tool.tar.gz
    - ./tool install
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if f[0].Line == 0 {
		t.Error("expected non-zero line number")
	}
}

func TestGL020_Commands(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		want         int
	}{
		{"curl -o", "curl -sSL -o tool.tgz https://example.com/tool.tgz", 1},
		{"curl -O cluster", "curl -sSLO https://example.com/tool.tgz", 1},
		{"curl --output=", "curl --output=tool.tgz https://example.com/tool.tgz", 1},
		{"wget", "wget https://example.com/tool.tgz", 1},
		{"sudo wget", "sudo wget -q https://example.com/tool.tgz", 1},
		{"curl in a substitution", "TGZ=$(curl -sSLo tool.tgz https://example.com/tool.tgz)", 1},
		{"wget as an apt package", "apt-get install -y curl wget ca-certificates --no-install-recommends", 0},
		{"curl to stdout", "curl -sSL https://example.com/api | jq .", 0},
		{"curl -o /dev/null probe", "curl --retry 10 --output /dev/null http://app:8080", 0},
		{"curl -o - into jq", "curl -sSL -o - https://example.com/x | jq .", 0},
		{"wget -qO- into grep", "wget -qO- https://example.com/x | grep ok", 0},
		{"wget -O /dev/null", "wget -O /dev/null http://app:8080", 0},
		{"wget --spider", "wget --spider http://app:8080", 0},
		{"curl in quoted text", `echo "use curl -O to fetch"`, 0},
		{"no-install-recommends", "apt install curl python3 --no-install-recommends", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings020(t, "job:\n  script:\n    - '"+strings.ReplaceAll(tc.script, "'", "''")+"'\n")
			if len(f) != tc.want {
				t.Fatalf("expected %d findings, got %d", tc.want, len(f))
			}
		})
	}
}

// The finding points at the line of a block that downloads, not the block start.
func TestGL020_BlockLine(t *testing.T) {
	f := findings020(t, `
job:
  script:
    - |
      apt-get install -y wget
      echo ready
      wget https://example.com/tool.tgz
`)
	if len(f) != 1 || f[0].Line != 7 {
		t.Fatalf("expected one finding on line 7, got %v", f)
	}
}

func TestGL020_StdoutIntoFiles(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{"wget -qO- https://example.com/x.tar.gz | tar -xz", 1},
		{"curl -sSL https://example.com/x.tar.gz | tar xz -C /usr/local", 1},
		{"curl -sSL https://example.com/x > tool", 1},
		{"curl.exe -O https://example.com/x.py", 1},
		{"curl -sSL https://example.com/x > /dev/null", 0},
		{"curl -sSL https://example.com/x 2>&1 | grep ok", 0},
		{"curl -sSL https://example.com/api | jq -r .tag", 0},
	} {
		f := findings020(t, "job:\n  script:\n    - '"+strings.ReplaceAll(tc.script, "'", "''")+"'\n")
		if len(f) != tc.want {
			t.Errorf("%s: expected %d findings, got %d", tc.script, tc.want, len(f))
		}
	}
}

func TestGL020_Wrappers(t *testing.T) {
	for _, script := range []string{
		"timeout 60 wget https://example.com/x.tgz",
		"retry 3 10 curl -sSLo x.tgz https://example.com/x.tgz",
		"wget https://example.com/x.tar.xz -O - | xzcat | tar -x",
	} {
		if f := findings020(t, "job:\n  script:\n    - '"+script+"'\n"); len(f) != 1 {
			t.Errorf("%s: expected 1 finding, got %d", script, len(f))
		}
	}
}

func TestGL020_APICalls(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{`curl -s -X POST -H "Content-Type: application/json" -d @req.json https://api.example.com/v1/apps > resp.json`, 0},
		{`curl --data-binary @payload https://api.example.com -o resp.json`, 0},
		{`curl -XPUT https://api.example.com/x -o out.json`, 0},
		{`curl -X GET https://example.com/tool.tgz -o tool.tgz`, 1},
	} {
		if f := findings020(t, "job:\n  script:\n    - '"+strings.ReplaceAll(tc.script, "'", "''")+"'\n"); len(f) != tc.want {
			t.Errorf("%s: expected %d, got %d", tc.script, tc.want, len(f))
		}
	}
}

// A curl that writes out the status code is a probe, also when it keeps the
// body for an error message (#990).
func TestGL020_StatusProbe(t *testing.T) {
	for _, tc := range []struct {
		line string
		want int
	}{
		{`code=$(curl -sS -o /tmp/response.json -w '%{http_code}' https://api.example.com/health)`, 0},
		{`curl -s --output body.txt --write-out "%{response_code}" https://api.example.com/health`, 0},
		{`curl -sSLo tool.tar.gz https://example.com/tool.tar.gz`, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - "+strconv.Quote(tc.line)+"\n"), "test.yml")
		if err != nil {
			t.Fatal(err)
		}
		if got := len(GL020.Check(doc.Root, "test.yml")); got != tc.want {
			t.Errorf("%s: got %d findings, want %d", tc.line, got, tc.want)
		}
	}
}

func TestCurlStatusProbe_Forms(t *testing.T) {
	for _, args := range [][]string{
		{"-s", "--write-out=%{http_code}", "http://app"},
		{"-s", "-w%{response_code}", "http://app"},
		{"-w", "%{http_code}", "http://app"},
	} {
		if !curlStatusProbe(args) {
			t.Errorf("%v: not a status probe", args)
		}
	}
	if curlStatusProbe([]string{"-w", "%{size_download}", "http://app"}) {
		t.Error("-w without a status code is not a probe")
	}
}

// Comparing the download with a tracked copy verifies it (#1056).
func TestGL020_CompareWithTrackedCopy(t *testing.T) {
	for _, tc := range []struct {
		lines string
		want  int
	}{
		{"    - curl -fsSLo schema.json https://example.com/schema.json\n    - diff schema.json vendor/schema.json\n", 0},
		{"    - curl -fsSL https://example.com/schema.json -o /tmp/schema.json\n    - cmp -s /tmp/schema.json schema.json\n", 0},
		{"    - wget -O upstream.yml https://example.com/ci.yml\n    - git diff --no-index --exit-code upstream.yml ci/ci.yml\n", 0},
		{"    - |\n      curl -fsSLO https://example.com/LICENSE.txt\n      diff -q LICENSE.txt LICENSE\n", 0},
		{"    - curl -fsSLo schema.json https://example.com/schema.json\n    - diff a.txt b.txt\n", 1},
		{"    - curl -fsSLo schema.json https://example.com/schema.json\n    - git diff --exit-code\n", 1},
		{"    - curl -fsSLo schema.json https://example.com/schema.json\n    - git diff schema.json\n", 1},
	} {
		if got := len(findings020(t, "job:\n  script:\n"+tc.lines)); got != tc.want {
			t.Errorf("%q: got %d findings, want %d", tc.lines, got, tc.want)
		}
	}
}

// A download from the pipeline's own project is guarded by GitLab (#1056).
func TestGL020_OwnProject_NoFinding(t *testing.T) {
	for _, line := range []string{
		`curl -fsSLo pkg.tgz --header "JOB-TOKEN: $CI_JOB_TOKEN" "$CI_API_V4_URL/projects/$CI_PROJECT_ID/packages/generic/pkg/1.0/pkg.tgz"`,
		`wget -O report.json "${CI_PROJECT_URL}/-/jobs/artifacts/main/raw/report.json?job=test"`,
	} {
		if f := findings020(t, "job:\n  script:\n    - '"+line+"'\n"); len(f) != 0 {
			t.Errorf("%s: got %v, want no finding", line, f)
		}
	}
	for _, line := range []string{
		`curl -fsSLo x "https://evil.example/$CI_API_V4_URL"`,
		`curl -fsSLO "$CI_SERVER_URL/group/tools/-/raw/main/tool.sh"`,
		`curl -fsSLo x "$CI_API_V4_URL/projects/42/packages/generic/tool/1.0/tool"`,
	} {
		if f := findings020(t, "job:\n  script:\n    - '"+line+"'\n"); len(f) != 1 {
			t.Errorf("%s: got %d findings, want 1", line, len(f))
		}
	}
}
