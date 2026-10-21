// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type Rule interface {
	ID() string
	Check(doc *yaml.Node, file string) []finding.Finding
}

// SpecRule is implemented by rules that also read the `spec:` header of a
// two-document file. The parser keeps that header apart from the linted body,
// so Check alone never sees it.
type SpecRule interface {
	CheckWithSpec(spec, doc *yaml.Node, file string) []finding.Finding
}
