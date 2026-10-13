package parser

import (
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
