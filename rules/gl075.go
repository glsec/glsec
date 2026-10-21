// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
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
	var findings []finding.Finding
	for _, item := range parser.IncludeItems(parser.FindKey(mapping, "include")) {
		findings = append(findings, r.checkIncludeItem(item, file)...)
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
		if path, ok := serverRelativeComponent(component.Value); ok {
			return r.flagServerRelative(component, file, path)
		}
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
	if hasDotSegment(normalized) {
		return gl075Finding(node, file, dotSegmentMessage)
	}
	if registryAllowed(host, normalized, r.allowedSources) {
		return nil
	}
	return gl075Finding(node, file, fmt.Sprintf(msgFmt, node.Value))
}

// flagServerRelative checks a component on the scanning instance
// ($CI_SERVER_FQDN/<path>). The host is unknown statically, so only allowlist
// entries that name a namespace, or spell the server variable out, can match.
func (r *gl075) flagServerRelative(node *yaml.Node, file, path string) []finding.Finding {
	if ownProjectPrefix.MatchString(path) {
		return nil
	}
	if path == "" || strings.Contains(path, "$") {
		return nil
	}
	if hasDotSegment(path) {
		return gl075Finding(node, file, dotSegmentMessage)
	}
	for _, entry := range r.allowedSources {
		e := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(entry), "/"))
		if rest, ok := serverRelativeComponent(e); ok {
			e = rest
		} else if strings.ContainsAny(firstPathSegment(e), ".:") {
			continue // names a host, which may not be this instance
		}
		if e != "" && (path == e || strings.HasPrefix(path, e+"/")) {
			return nil
		}
	}
	return gl075Finding(node, file, fmt.Sprintf("component include %q is from a namespace not in the allowed_include_sources allowlist", node.Value))
}

const dotSegmentMessage = "include source contains a \".\" or \"..\" path segment — it is never treated as allowlisted; use the canonical path"

func gl075Finding(node *yaml.Node, file, msg string) []finding.Finding {
	return []finding.Finding{{
		RuleID:   "GL075",
		Severity: finding.Warn,
		Message:  msg,
		File:     file,
		Line:     node.Line,
		Col:      node.Column,
	}}
}

// serverPrefix matches the predefined variables GitLab documents for writing a
// component reference on the current instance.
var serverPrefix = regexp.MustCompile(`(?i)^\$(?:\{CI_SERVER_(?:FQDN|HOST)\}|CI_SERVER_(?:FQDN|HOST)\b)/`)

// ownProjectPrefix matches a path that starts in the scanned project's own
// namespace, as in GitLab's $CI_SERVER_FQDN/$CI_PROJECT_PATH/my-component@1.0.
var ownProjectPrefix = regexp.MustCompile(`(?i)^\$(?:\{CI_PROJECT_(?:PATH|NAMESPACE|ROOT_NAMESPACE)\}|CI_PROJECT_(?:PATH|NAMESPACE|ROOT_NAMESPACE)\b)(?:/|$)`)

// serverRelativeComponent returns the lower-cased path of a component written
// as $CI_SERVER_FQDN/<path>[@version].
func serverRelativeComponent(value string) (string, bool) {
	loc := serverPrefix.FindStringIndex(value)
	if loc == nil {
		return "", false
	}
	path := value[loc[1]:]
	if at := strings.LastIndex(path, "@"); at >= 0 {
		path = path[:at]
	}
	return strings.ToLower(path), true
}

// hasDotSegment reports whether a path has a "." or ".." segment, also
// percent-encoded. Prefix matching on such a path says nothing about where it
// resolves.
func hasDotSegment(path string) bool {
	for _, seg := range strings.Split(strings.ToLower(path), "/") {
		seg = strings.ReplaceAll(seg, "%2e", ".")
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
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
