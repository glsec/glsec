package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/version"
	"gopkg.in/yaml.v3"
)

const DefaultFile = ".glsec.yml"

// RuleConfig holds per-rule overrides. It can be specified as either a plain
// severity string or a mapping:
//
//	GL001: warn                  # flat form
//	GL001:                       # nested form
//	  severity: warn
type RuleConfig struct {
	Severity string // "error", "warn", "info", or "off"; empty = use rule default
}

// UnmarshalYAML allows RuleConfig to accept both a plain scalar ("warn") and a
// mapping ({ severity: warn }) in the config file.
func (r *RuleConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		r.Severity = value.Value
		return nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(value.Content); i += 2 {
			key := value.Content[i].Value
			val := value.Content[i+1].Value
			switch key {
			case "severity":
				r.Severity = val
			default:
				return fmt.Errorf("unknown rule config key %q", key)
			}
		}
		return nil
	default:
		return fmt.Errorf("rule config must be a string or mapping")
	}
}

// Config holds the parsed contents of a .glsec.yml file.
type Config struct {
	// Rules maps rule ID to a per-rule override.
	Rules map[string]RuleConfig `yaml:"rules"`
	// MinSeverity filters out findings below this level.
	MinSeverity string `yaml:"min-severity"`
	// GitLabVersion is the target GitLab version (e.g. "16.0").
	// Rules requiring a higher version are skipped.
	GitLabVersion string `yaml:"gitlab-version"`
	// TrustedHosts is a list of hostnames or CIDRs whose HTTP URLs are never flagged.
	TrustedHosts []string `yaml:"trusted-hosts"`
	// Strict makes warn findings count as errors for exit-code purposes.
	Strict bool `yaml:"strict"`
	// NoExitCodes makes glsec always exit 0 on successful execution,
	// regardless of findings. Useful for advisory runs.
	NoExitCodes bool `yaml:"no-exit-codes"`
}

// Default returns a Config with no overrides.
func Default() *Config {
	return &Config{
		Rules:       map[string]RuleConfig{},
		MinSeverity: "",
	}
}

// Load reads and parses a config file. Returns Default() if the file does not
// exist and path is the default filename.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: user-supplied config path
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && path == DefaultFile {
			return Default(), nil
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	return parse(data, path)
}

func parse(data []byte, path string) (*Config, error) {
	// Decode into a raw node first so we can detect unknown keys.
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if root.Kind == 0 {
		return Default(), nil
	}

	mapping := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		mapping = root.Content[0]
	}
	if mapping.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: config must be a YAML mapping", path)
	}

	if err := checkUnknownKeys(mapping, path); err != nil {
		return nil, err
	}

	var cfg Config
	if err := root.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Rules == nil {
		cfg.Rules = map[string]RuleConfig{}
	}

	if err := cfg.validate(path); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var allowedTopLevelKeys = map[string]bool{
	"rules":          true,
	"min-severity":   true,
	"gitlab-version": true,
	"trusted-hosts":  true,
	"strict":         true,
	"no-exit-codes":  true,
}

func checkUnknownKeys(mapping *yaml.Node, path string) error {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key := mapping.Content[i].Value
		if !allowedTopLevelKeys[key] {
			return fmt.Errorf("%s:%d: unknown config key %q", path, mapping.Content[i].Line, key)
		}
	}
	return nil
}

var validSeverities = map[string]bool{
	"error": true,
	"warn":  true,
	"info":  true,
	"off":   true,
}

func (c *Config) validate(path string) error {
	for id, rc := range c.Rules {
		if !strings.HasPrefix(id, "GL") {
			return fmt.Errorf("%s: rules: invalid rule ID %q (must start with GL)", path, id)
		}
		if !validSeverities[rc.Severity] {
			return fmt.Errorf("%s: rules.%s: invalid severity %q (use error, warn, info, or off)", path, id, rc.Severity)
		}
	}
	if c.MinSeverity != "" {
		if !validSeverities[c.MinSeverity] || c.MinSeverity == "off" {
			return fmt.Errorf("%s: min-severity: invalid value %q (use error, warn, or info)", path, c.MinSeverity)
		}
	}
	if c.GitLabVersion != "" {
		if _, err := version.Parse(c.GitLabVersion); err != nil {
			return fmt.Errorf("%s: gitlab-version: %w", path, err)
		}
	}
	return nil
}

// RuleEnabled returns false if the rule is set to "off" in the config.
func (c *Config) RuleEnabled(id string) bool {
	rc, ok := c.Rules[id]
	return !ok || rc.Severity != "off"
}

// ApplySeverity returns the effective severity for a finding, applying any
// rule-level override from the config.
func (c *Config) ApplySeverity(f finding.Finding) finding.Finding {
	rc, ok := c.Rules[f.RuleID]
	if !ok || rc.Severity == "" || rc.Severity == "off" {
		return f
	}
	f.Severity = finding.Severity(rc.Severity)
	return f
}

// severityLevel maps severity to a comparable integer (higher = more severe).
var severityLevel = map[finding.Severity]int{
	finding.Error: 3,
	finding.Warn:  2,
	finding.Info:  1,
}

// AboveMinSeverity returns true if f meets or exceeds the configured
// min-severity. If min-severity is unset, all findings pass.
func (c *Config) AboveMinSeverity(f finding.Finding) bool {
	if c.MinSeverity == "" {
		return true
	}
	min := severityLevel[finding.Severity(c.MinSeverity)]
	return severityLevel[f.Severity] >= min
}
