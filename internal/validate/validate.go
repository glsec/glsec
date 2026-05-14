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
	if ext != ".yml" && ext != ".yaml" {
		warnings = append(warnings, fmt.Sprintf("%s: file does not have a .yml or .yaml extension", path))
	}

	mapping := doc.MappingNode()
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
// "script" key).
func hasGitLabContent(mapping *yaml.Node) bool {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key := mapping.Content[i].Value
		val := mapping.Content[i+1]
		if knownKeys[key] {
			return true
		}
		if val.Kind == yaml.MappingNode && hasKey(val, "script") {
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
