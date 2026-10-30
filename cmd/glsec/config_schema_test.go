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
	Defs        map[string]*schemaNode `json:"$defs"`
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

	if got := schema.Defs["ruleId"].Enum; !reflect.DeepEqual(got, ids) {
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
