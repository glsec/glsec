package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl075 struct {
	allowedSources []string
}

var GL075 = &gl075{}

func (r *gl075) ID() string { return "GL075" }

// SetAllowedIncludeSources configures the opt-in include-source allowlist. When
// empty, the rule is a no-op and flags nothing (so the default behaviour does
// not complain about every include).
func (r *gl075) SetAllowedIncludeSources(sources []string) {
	r.allowedSources = sources
}

func (r *gl075) Check(doc *yaml.Node, file string) []finding.Finding {
	if len(r.allowedSources) == 0 {
		return nil
	}

	mapping := parser.Unwrap(doc)
	includeNode := parser.FindKey(mapping, "include")
	if includeNode == nil {
		return nil
	}

	var findings []finding.Finding
	switch includeNode.Kind {
	case yaml.SequenceNode:
		for _, item := range includeNode.Content {
			if item.Kind == yaml.MappingNode {
				findings = append(findings, r.checkIncludeItem(item, file)...)
			}
		}
	case yaml.MappingNode:
		findings = append(findings, r.checkIncludeItem(includeNode, file)...)
	}
	return findings
}

func (r *gl075) checkIncludeItem(node *yaml.Node, file string) []finding.Finding {
	if remote := parser.FindKey(node, "remote"); remote != nil {
		host, normalized := remoteIncludeSource(remote.Value)
		return r.flagIfDisallowed(remote, file, host, normalized,
			"remote include %q is from a host not in the allowed_include_sources allowlist")
	}
	if component := parser.FindKey(node, "component"); component != nil {
		host, normalized := componentIncludeSource(component.Value)
		return r.flagIfDisallowed(component, file, host, normalized,
			"component include %q is from a source not in the allowed_include_sources allowlist")
	}
	if project := parser.FindKey(node, "project"); project != nil {
		host, normalized := projectIncludeSource(project.Value)
		return r.flagIfDisallowed(project, file, host, normalized,
			"project include %q is from a namespace not in the allowed_include_sources allowlist")
	}
	// local: and template: are not external sources.
	return nil
}

func (r *gl075) flagIfDisallowed(node *yaml.Node, file, host, normalized, msgFmt string) []finding.Finding {
	// Empty or variable-expanded sources cannot be resolved statically.
	if host == "" || strings.Contains(normalized, "$") {
		return nil
	}
	if registryAllowed(host, normalized, r.allowedSources) {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "GL075",
		Severity: finding.Warn,
		Message:  fmt.Sprintf(msgFmt, node.Value),
		File:     file,
		Line:     node.Line,
		Col:      node.Column,
	}}
}

// projectIncludeSource maps "my-group/sub/project" to (namespace, fullPath).
func projectIncludeSource(value string) (host, normalized string) {
	if value == "" {
		return "", ""
	}
	return strings.ToLower(firstPathSegment(value)), strings.ToLower(value)
}

// componentIncludeSource maps "gitlab.com/org/comp@1.0" to (host, host/path).
func componentIncludeSource(value string) (host, normalized string) {
	if value == "" {
		return "", ""
	}
	src := value
	if at := strings.LastIndex(src, "@"); at >= 0 {
		src = src[:at]
	}
	return strings.ToLower(firstPathSegment(src)), strings.ToLower(src)
}

// remoteIncludeSource maps "https://host/path/file.yml" to (host, host/path).
func remoteIncludeSource(value string) (host, normalized string) {
	s := value
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if s == "" {
		return "", ""
	}
	// drop query string / fragment
	if q := strings.IndexAny(s, "?#"); q >= 0 {
		s = s[:q]
	}
	s = strings.ToLower(s)
	host = firstPathSegment(s)
	return host, s
}

func firstPathSegment(path string) string {
	if i := strings.Index(path, "/"); i >= 0 {
		return path[:i]
	}
	return path
}
