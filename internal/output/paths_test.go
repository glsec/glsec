// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/baseline"
	"github.com/glsec/glsec/internal/finding"
)

func TestReportPaths(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "repo")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	for _, tc := range []struct {
		name, file, want string
		local            bool
	}{
		{"relative", "ci/build.yml", "ci/build.yml", true},
		{"absolute inside", filepath.Join(cwd, "ci", "build.yml"), "ci/build.yml", true},
		{"absolute outside", filepath.Join(root, "outside.yml"), filepath.Join(root, "outside.yml"), false},
		{"sibling prefix", filepath.Join(root, "repo-other", "build.yml"), filepath.Join(root, "repo-other", "build.yml"), false},
		{"relative outside", "../outside.yml", "../outside.yml", false},
	} {
		for _, format := range []Format{FormatJSON, FormatSARIF, FormatCodeClimate, FormatJUnit, FormatGitLabSAST} {
			t.Run(tc.name+"/"+string(format), func(t *testing.T) {
				fs := []finding.Finding{{RuleID: "GL001", Severity: finding.Warn, File: tc.file, Line: 7, Message: "mutable image"}}
				var buf bytes.Buffer
				if err := Write(&buf, format, fs, 1, false, false); err != nil {
					t.Fatal(err)
				}
				var got string
				switch format {
				case FormatJSON:
					var out jsonOutput
					if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					got = out.Findings[0].File
				case FormatSARIF:
					var out sarifLog
					if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					location := out.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
					got = location.URI
					if want := sarifURI(tc.want); got != want {
						t.Errorf("uri = %q, want %q", got, want)
					}
					got = tc.want
					if hasBase := location.URIBaseID == "%SRCROOT%"; hasBase != tc.local {
						t.Errorf("SRCROOT present = %v, want %v", hasBase, tc.local)
					}
				case FormatCodeClimate:
					var out []codeClimateIssue
					if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					got = out[0].Location.Path
				case FormatGitLabSAST:
					var out gitlabSASTReport
					if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					got = out.Vulnerabilities[0].Location.File
				case FormatJUnit:
					var out junitTestsuites
					if err := xml.Unmarshal(buf.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					got = strings.TrimSuffix(out.Suites[0].Cases[0].Classname, ":7")
					if !strings.Contains(out.Suites[0].Cases[0].Failure.Text, tc.want+":7") {
						t.Error("failure text has inconsistent path")
					}
				}
				if got != tc.want {
					t.Errorf("path = %q, want %q", got, tc.want)
				}
				if fs[0].File != tc.file {
					t.Error("writer mutated the finding")
				}
			})
		}
	}
}

func TestCodeQualityPathsHaveStableFingerprints(t *testing.T) {
	t.Chdir(t.TempDir())
	abs, err := filepath.Abs("ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var fingerprints []string
	for _, file := range []string{"ci.yml", abs} {
		var buf bytes.Buffer
		if err := WriteCodeClimate(&buf, []finding.Finding{{RuleID: "GL001", File: file, Line: 7}}); err != nil {
			t.Fatal(err)
		}
		var out []codeClimateIssue
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		fingerprints = append(fingerprints, out[0].Fingerprint)
	}
	if fingerprints[0] != fingerprints[1] {
		t.Error("absolute and relative invocation produce different fingerprints")
	}
}

func TestJSONReportRemainsUsableAsBaseline(t *testing.T) {
	t.Chdir(t.TempDir())
	abs, err := filepath.Abs("ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := finding.Finding{RuleID: "GL001", File: abs, Line: 7, Message: "mutable image"}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []finding.Finding{f}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("base.json", buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := baseline.Load("base.json")
	if err != nil {
		t.Fatal(err)
	}
	if b.IsNew(f) {
		t.Error("snapshot does not match a scan using the same absolute path")
	}
}

func TestReportPathWithoutWorkingDirectory(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "ci.yml")
	if got, local := reportPath(abs, ""); got != abs || local {
		t.Errorf("without cwd: got (%q, %v), want original absolute path", got, local)
	}
}

func TestSARIFURI(t *testing.T) {
	cases := map[string]string{
		"ci/build.yml":               "ci/build.yml",
		"ci/my pipelines/deploy.yml": "ci/my%20pipelines/deploy.yml",
		"../outside.yml":             "../outside.yml",
		"ci/50%.yml":                 "ci/50%25.yml",
	}
	if runtime.GOOS == "windows" {
		cases[`C:\Users\ci\my file.yml`] = "file:///C:/Users/ci/my%20file.yml"
	} else {
		cases["/home/ci/my file.yml"] = "file:///home/ci/my%20file.yml"
	}
	for in, want := range cases {
		if got := sarifURI(in); got != want {
			t.Errorf("sarifURI(%q) = %q, want %q", in, got, want)
		}
	}
}
