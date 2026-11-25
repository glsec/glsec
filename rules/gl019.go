// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl019 struct{}

var GL019 = &gl019{}

func (r *gl019) ID() string { return "GL019" }

// CheckDocument skips a child pipeline that runs entirely under the
// resource_group lock of the trigger jobs starting it, and the files it
// includes (#1483). GitLab holds that lock until the child finishes.
func (r *gl019) CheckDocument(doc *parser.Document, file string) []finding.Finding {
	if doc.LockedByParent || doc.IncludedBy != nil && doc.IncludedBy.LockedByParent {
		return nil
	}
	return r.Check(doc.Root, file)
}

func (r *gl019) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !runsInheritedJob(in, name, job) || !isSensitiveJob(in, job, false) {
			return
		}
		if in.Key(job, "resource_group") != nil {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL019",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"job %q deploys or publishes but has no resource_group: — concurrent pipeline runs can cause race conditions or partial deploys",
				name.Value,
			),
			File: file,
			Line: name.Line,
			Col:  name.Column,
		})
	})

	return findings
}
