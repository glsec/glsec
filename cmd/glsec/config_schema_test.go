// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/rules"
)

const configSchemaPath = "../../schema/glsec.schema.json"

type schemaNode struct {
	Description string                 `json:"description"`
	Properties  map[string]*schemaNode `json:"properties"`
	Definitions map[string]*schemaNode `json:"definitions"`
	Enum        []string               `json:"enum"`
}

// ruleIDEnum is the generated line in the schema that lists the rule IDs.
// \r?: Windows checks the file out with CRLF line endings.
var ruleIDEnum = regexp.MustCompile(`("ruleId": \{\r?\n\s*"description": "[^"]*",\r?\n\s*"enum": )\[[^\]]*\]`)

// TestConfigSchema keeps schema/glsec.schema.json in step with the config
// parser and the rule registry (#832). A new rule only needs
// go test ./cmd/glsec -run TestConfigSchema -update
func TestConfigSchema(t *testing.T) {
	raw, err := os.ReadFile(configSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rules.All() {
		ids = append(ids, r.ID())
	}
	sort.Strings(ids)
	if *updateCorpus {
		quoted, _ := json.Marshal(ids)
		updated := ruleIDEnum.ReplaceAll(raw, []byte("${1}"+strings.ReplaceAll(string(quoted), `","`, `", "`)))
		if err := os.WriteFile(configSchemaPath, updated, 0o600); err != nil { //nolint:gosec // G703: the repository's own schema file
			t.Fatal(err)
		}
		raw = updated
	}
	if !ruleIDEnum.Match(raw) {
		t.Fatal("the schema has no generated ruleId enum")
	}
	var schema schemaNode
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}

	var inSchema []string
	for k, p := range schema.Properties {
		inSchema = append(inSchema, k)
		if p.Description == "" {
			t.Errorf("%s has no description", k)
		}
	}
	sort.Strings(inSchema)
	if keys := config.Keys(); !reflect.DeepEqual(inSchema, keys) {
		t.Errorf("schema keys %v, config keys %v", inSchema, keys)
	}

	var sc []string
	for i := range reflect.TypeFor[config.ShellCheckConfig]().NumField() {
		sc = append(sc, reflect.TypeFor[config.ShellCheckConfig]().Field(i).Tag.Get("yaml"))
	}
	var scSchema []string
	for k := range schema.Properties["shellcheck"].Properties {
		scSchema = append(scSchema, k)
	}
	sort.Strings(sc)
	sort.Strings(scSchema)
	if !reflect.DeepEqual(sc, scSchema) {
		t.Errorf("shellcheck: schema keys %v, config keys %v", scSchema, sc)
	}

	if got := schema.Definitions["ruleId"].Enum; !reflect.DeepEqual(got, ids) {
		t.Errorf("the schema's rule IDs differ from the registry; run go test ./cmd/glsec -run TestConfigSchema -update\nschema: %v\nrules:  %v", got, ids)
	}
}

// The example in docs is what glsec reads; CI checks it against the schema.
func TestConfigExampleLoads(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "docs", "glsec.example.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var unknown []string
	set := map[string]bool{}
	for id := range cfg.Rules {
		set[id] = true
	}
	unknown = unknownRuleIDs(set)
	if len(unknown) > 0 {
		t.Errorf("the example configures unknown rules %v", unknown)
	}
	raw, _ := os.ReadFile(filepath.Join("..", "..", "docs", "glsec.example.yml"))
	for _, key := range config.Keys() {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:`).Match(raw) {
			t.Errorf("the example leaves out %s", key)
		}
	}
}

func TestRun_WarnsAboutUnknownRuleIDsInConfig(t *testing.T) {
	code, _, stderr := runCLI(t, map[string]string{
		"ci.yml":     cleanPipeline,
		".glsec.yml": "rules:\n  GL10: off\n  GL001: warn\n  SC2086: off\n",
	}, "ci.yml")
	if code != 0 {
		t.Errorf("exit %d, want 0: an unknown rule ID is a warning", code)
	}
	if !strings.Contains(stderr, `warning: .glsec.yml: rules: unknown rule ID "GL10"`) {
		t.Errorf("no warning for GL10:\n%s", stderr)
	}
	if strings.Contains(stderr, "GL001") || strings.Contains(stderr, "SC2086") {
		t.Errorf("a known rule or ShellCheck code is reported:\n%s", stderr)
	}
}

func TestRun_RecursivePatternsInConfig(t *testing.T) {
	code, _, stderr := runCLI(t, map[string]string{
		"ci/pipeline.yml": errorPipeline,
		".glsec.yml":      "recursive_patterns:\n  - ci/pipeline.yml\n",
	}, "--recursive", ".")
	if code != 1 || strings.Contains(stderr, "unknown config key") {
		t.Errorf("exit %d, want 1 with ci/pipeline.yml scanned:\n%s", code, stderr)
	}
}

// TestConfigSchema_GitLabVersionDivergence exercises representative
// gitlab-version values against both schema/glsec.schema.json and the CLI
// parser, pinning the intended divergence where the JSON schema accepts
// positive numbers < 1 (such as 0.5) that internal/version rejects.
func TestConfigSchema_GitLabVersionDivergence(t *testing.T) {
	raw, err := os.ReadFile(configSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Properties map[string]struct {
			AnyOf []struct {
				Type             string   `json:"type"`
				Pattern          string   `json:"pattern"`
				ExclusiveMinimum *float64 `json:"exclusiveMinimum"`
			} `json:"anyOf"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	gvSchema := doc.Properties["gitlab-version"]
	if len(gvSchema.AnyOf) == 0 {
		t.Fatal("schema missing gitlab-version anyOf")
	}

	matchesSchema := func(val any) bool {
		for _, branch := range gvSchema.AnyOf {
			switch branch.Type {
			case "string":
				s, ok := val.(string)
				if !ok {
					continue
				}
				if branch.Pattern == "" || regexp.MustCompile(branch.Pattern).MatchString(s) {
					return true
				}
			case "number":
				n, ok := val.(float64)
				if !ok {
					continue
				}
				if branch.ExclusiveMinimum == nil || n > *branch.ExclusiveMinimum {
					return true
				}
			}
		}
		return false
	}

	for _, tc := range []struct {
		name       string
		yamlVal    string
		jsonVal    any
		wantSchema bool
		wantExit   int
	}{
		{"quoted major.minor", `"17.4"`, "17.4", true, 0},
		{"numeric major.minor", `17.4`, 17.4, true, 0},
		{"quoted major", `"17"`, "17", true, 0},
		{"numeric major", `17`, float64(17), true, 0},
		{"numeric < 1 (pinned divergence)", `0.5`, 0.5, true, 2},
		{"quoted < 1", `"0.5"`, "0.5", false, 2},
		{"negative number", `-1`, float64(-1), false, 2},
		{"non-version string", `"abc"`, "abc", false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesSchema(tc.jsonVal); got != tc.wantSchema {
				t.Errorf("schema match(%v) = %v, want %v", tc.jsonVal, got, tc.wantSchema)
			}
			code, _, stderr := runCLI(t, map[string]string{
				"ci.yml":     cleanPipeline,
				".glsec.yml": "gitlab-version: " + tc.yamlVal + "\n",
			}, "ci.yml")
			if code != tc.wantExit {
				t.Errorf("CLI exit = %d, want %d; stderr:\n%s", code, tc.wantExit, stderr)
			}
		})
	}
}
