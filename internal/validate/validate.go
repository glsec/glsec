// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// File validates that path is a plausible GitLab CI file.
// It returns any warnings (non-fatal) and a fatal error if the file
// cannot be linted meaningfully.
func File(path string, doc *parser.Document) (warnings []string, err error) {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yml" && ext != ".yaml" && path != parser.StdinName {
		warnings = append(warnings, fmt.Sprintf("%s: file does not have a .yml or .yaml extension", path))
	}

	for _, line := range doc.IgnoredDocuments {
		warnings = append(warnings, fmt.Sprintf("%s:%d: document ignored: after a spec: header GitLab runs only the last document", path, line))
	}

	mapping := doc.MappingNode()
	for i := 0; mapping.Kind == yaml.MappingNode && i+1 < len(mapping.Content); i += 2 {
		if key := mapping.Content[i]; parser.IsKeywordJob(key) {
			warnings = append(warnings, fmt.Sprintf("%s:%d: %s: has job keywords, so GitLab runs it as a job named %q and it sets no %s; glsec scans it as that job", path, key.Line, key.Value, key.Value, map[string]string{"default": "defaults", "workflow": "workflow rules"}[key.Value]))
		}
	}
	if mapping.Kind != yaml.MappingNode {
		return warnings, fmt.Errorf("%s: not a valid GitLab CI file: expected a top-level mapping", path)
	}

	if !hasGitLabContent(mapping) {
		return warnings, fmt.Errorf("%s: not a valid GitLab CI file: no recognisable GitLab CI content", path)
	}

	return warnings, nil
}

// knownKeys are GitLab CI reserved top-level keys that are not job definitions.
var knownKeys = map[string]bool{
	"stages":        true,
	"variables":     true,
	"default":       true,
	"workflow":      true,
	"include":       true,
	"image":         true,
	"services":      true,
	"cache":         true,
	"before_script": true,
	"after_script":  true,
}

// hasGitLabContent returns true if the mapping contains at least one known
// top-level GitLab CI key or at least one job-like entry (mapping with a
// "script", "run" or "trigger" key). run: is the CI/CD Steps alternative to
// script: and is mutually exclusive with it, so a pipeline built entirely from
// steps has no script: key anywhere. A trigger job has neither: a parent
// pipeline may consist of nothing but triggers for its children.
func hasGitLabContent(mapping *yaml.Node) bool {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key := mapping.Content[i].Value
		val := mapping.Content[i+1]
		if knownKeys[key] {
			return true
		}
		if val.Kind == yaml.MappingNode && (hasKey(val, "script") || hasKey(val, "run") || hasKey(val, "trigger")) {
			return true
		}
	}
	return false
}

func hasKey(mapping *yaml.Node, key string) bool {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return true
		}
	}
	return false
}
