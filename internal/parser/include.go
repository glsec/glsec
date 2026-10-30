// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// IncludeItems returns the entries of an `include:` value as mapping nodes,
// whatever shape it was written in: a list, a single mapping, or plain strings.
// A string is the shorthand GitLab resolves as `remote:` when it is a URL and as
// `local:` otherwise; it is returned as a one-key mapping around the original
// node, so findings keep its position.
func IncludeItems(include *yaml.Node) []*yaml.Node {
	if include == nil {
		return nil
	}
	switch include.Kind {
	case yaml.ScalarNode:
		return []*yaml.Node{shorthandInclude(include)}
	case yaml.MappingNode:
		return []*yaml.Node{include}
	case yaml.SequenceNode:
		items := make([]*yaml.Node, 0, len(include.Content))
		for _, item := range include.Content {
			switch item.Kind {
			case yaml.ScalarNode:
				items = append(items, shorthandInclude(item))
			case yaml.MappingNode:
				items = append(items, item)
			}
		}
		return items
	}
	return nil
}

func shorthandInclude(value *yaml.Node) *yaml.Node {
	key := "local"
	lower := strings.ToLower(value.Value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		key = "remote"
	}
	return &yaml.Node{
		Kind:    yaml.MappingNode,
		Tag:     "!!map",
		Line:    value.Line,
		Column:  value.Column,
		Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: key, Line: value.Line, Column: value.Column}, value},
	}
}

// LocalIncludePaths returns the files a pipeline pulls in with a top-level
// `include:` of local files (#810): `local:` entries and the string
// shorthand, whatever their `rules:` say, since the file may be included.
// A path with a variable or an input can't be resolved without the
// pipeline's context and is left out. Paths may contain GitLab's wildcards;
// see MatchIncludeGlob.
func LocalIncludePaths(doc *yaml.Node) []string {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	var paths []string
	for _, item := range IncludeItems(FindKey(doc, "include")) {
		local := FindKey(item, "local")
		if local == nil || local.Kind != yaml.ScalarNode || local.Value == "" {
			continue
		}
		if strings.Contains(local.Value, "$") {
			continue
		}
		paths = append(paths, local.Value)
	}
	return paths
}

// IncludeGlob compiles a wildcard `include: local` path the way GitLab
// matches it against the repository's files: `*` stays within a directory,
// `**` crosses directories (`ci/**.yml`, `ci/**/*.yml`), `?` is one character
// and `{a,b}` either. The pattern is relative to the repository root, without
// a leading `/`. It returns nil for a path without wildcards.
func IncludeGlob(pattern string) *regexp.Regexp {
	if !strings.ContainsAny(pattern, "*?{") {
		return nil
	}
	var re strings.Builder
	re.WriteString(`^`)
	depth := 0
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case strings.HasPrefix(pattern[i:], "**/"):
			re.WriteString(`(?:.*/)?`)
			i += 2
		case strings.HasPrefix(pattern[i:], "**"):
			re.WriteString(`.*`)
			i++
		case c == '*':
			re.WriteString(`[^/]*`)
		case c == '?':
			re.WriteString(`[^/]`)
		case c == '{':
			re.WriteString(`(?:`)
			depth++
		case c == '}' && depth > 0:
			re.WriteString(`)`)
			depth--
		case c == ',' && depth > 0:
			re.WriteString(`|`)
		default:
			re.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if depth > 0 {
		return nil
	}
	re.WriteString(`$`)
	compiled, err := regexp.Compile(re.String())
	if err != nil {
		return nil
	}
	return compiled
}

// IncludeGlobDir returns the directory a wildcard pattern's matches are in:
// the part before the first wildcard, up to its last `/`.
func IncludeGlobDir(pattern string) string {
	static := pattern
	if i := strings.IndexAny(pattern, "*?{"); i >= 0 {
		static = pattern[:i]
	}
	if i := strings.LastIndexByte(static, '/'); i >= 0 {
		return static[:i]
	}
	return ""
}
