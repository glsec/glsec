// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Bool reads a boolean keyword the way GitLab does. Psych follows YAML 1.1,
// where a plain true, yes or on is true and false, no or off is false, in any
// case; yaml.v3 keeps all but true and false as strings. ok is false for
// anything else, including a quoted or tagged value and y or n.
func Bool(n *yaml.Node) (value, ok bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.TaggedStyle) != 0 {
		return false, false
	}
	switch strings.ToLower(n.Value) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	}
	return false, false
}

// IsTrue reports a boolean keyword set to true.
func IsTrue(n *yaml.Node) bool {
	v, ok := Bool(n)
	return ok && v
}

// IsFalse reports a boolean keyword set to false.
func IsFalse(n *yaml.Node) bool {
	v, ok := Bool(n)
	return ok && !v
}
