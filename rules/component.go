// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/rule"
)

// wholePipelineRules reason about a pipeline as a whole, so they cannot be
// evaluated against a CI/CD component template. A template is a fragment: the
// consuming pipeline supplies the surrounding configuration.
//
// Kept deliberately small. Rules that merely *read* a top-level key when it is
// present (GL043, GL074, GL080) degrade correctly on a fragment and stay
// enabled; only rules that fire on its absence belong here.
var wholePipelineRules = map[string]bool{
	// GL053 flags a missing top-level workflow: block. A component template
	// never has one, so it would fire on every template ever written.
	"GL053": true,
}

// AppliesToComponentTemplate reports whether a rule is meaningful when the file
// under analysis is a CI/CD component template rather than a full pipeline.
func AppliesToComponentTemplate(id string) bool {
	return !wholePipelineRules[id]
}

// Check runs a rule against a parsed document, handing the `spec:` header to
// rules that read it.
func Check(r rule.Rule, doc *parser.Document, file string) []finding.Finding {
	if sr, ok := r.(rule.SpecRule); ok && doc.Spec != nil {
		return sr.CheckWithSpec(doc.Spec, doc.Root, file)
	}
	return r.Check(doc.Root, file)
}
