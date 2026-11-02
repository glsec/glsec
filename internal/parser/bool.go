// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Bool reports whether n is a plain YAML 1.1 boolean scalar as GitLab's
// Psych parser would read it: unquoted true/yes/on or false/no/off in any
// case. Quoted values ("yes"), explicitly tagged values (!!str yes), y/n,
// and non-scalars return ok=false. yaml.v3 resolves a plain yes as !!str,
// so Style — not Tag — decides whether the value was quoted or tagged.
func Bool(n *yaml.Node) (value, ok bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false, false
	}
	if n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.TaggedStyle) != 0 {
		return false, false
	}
	switch strings.ToLower(n.Value) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}
