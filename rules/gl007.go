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

type gl007 struct{}

var GL007 = &gl007{}

func (r *gl007) ID() string { return "GL007" }

// entireVarRe matches an image ref that is entirely a single variable reference.
var entireVarRe = regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`)

// userControlledImageVars are GitLab predefined variables whose values are set
// by external actors (commit authors, MR creators) and can contain arbitrary strings.
var userControlledImageVars = []string{
	"CI_COMMIT_REF_NAME",
	"CI_COMMIT_REF_SLUG",
	"CI_COMMIT_BRANCH",
	"CI_COMMIT_TAG",
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"CI_PIPELINE_NAME",
}

func (r *gl007) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)
	globalVars := parser.FindKey(mapping, "variables")

	findings = append(findings, checkImageVarInjection(parser.FindKey(mapping, "image"), file, globalVars, nil)...)
	findings = append(findings, checkServicesVarInjection(parser.FindKey(mapping, "services"), file, globalVars, nil)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkImageVarInjection(parser.FindKey(def, "image"), file, globalVars, nil)...)
		findings = append(findings, checkServicesVarInjection(parser.FindKey(def, "services"), file, globalVars, nil)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		jobVars := parser.FindKey(job, "variables")
		for _, f := range checkImageVarInjection(parser.FindKey(job, "image"), file, globalVars, jobVars) {
			f.Job = name.Value
			findings = append(findings, f)
		}
		for _, f := range checkServicesVarInjection(parser.FindKey(job, "services"), file, globalVars, jobVars) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

// imageVarInFileLiteral reports whether a whole-variable image ref ($IMG) names
// a variable this file defines to a plain image literal, in the job's own
// variables: or the top-level variables:. A value that is itself a variable
// reference ($...) doesn't count, because it isn't resolvable to an image here.
func imageVarInFileLiteral(ref string, globalVars, jobVars *yaml.Node) bool {
	name := strings.Trim(ref, "${}")
	for _, vars := range []*yaml.Node{jobVars, globalVars} {
		for _, val := range varValues(vars, name) {
			if val != "" && !strings.Contains(val, "$") {
				return true
			}
		}
	}
	return false
}

func checkImageVarInjection(node *yaml.Node, file string, globalVars, jobVars *yaml.Node) []finding.Finding {
	if node == nil {
		return nil
	}
	ref, line, col := imageRef(node)
	if ref == "" {
		return nil
	}
	return imageVarFindings(ref, line, col, file, globalVars, jobVars)
}

func checkServicesVarInjection(node *yaml.Node, file string, globalVars, jobVars *yaml.Node) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		ref, line, col := imageRef(item)
		if ref == "" {
			continue
		}
		findings = append(findings, imageVarFindings(ref, line, col, file, globalVars, jobVars)...)
	}
	return findings
}

func imageVarFindings(ref string, line, col int, file string, globalVars, jobVars *yaml.Node) []finding.Finding {
	if entireVarRe.MatchString(ref) {
		if imageVarInFileLiteral(ref, globalVars, jobVars) {
			// The variable is set to a plain image literal in this file, so the
			// real trust boundary is editing the YAML — the same as writing the
			// image directly. An override from a project/group variable or a
			// manual run can still redirect it, so it is still worth pinning.
			return []finding.Finding{{
				RuleID:   "GL007",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"image %q is set from a CI variable that resolves to a literal in this file — pin the image directly; a project/group variable or a manual pipeline run could still override it",
					ref,
				),
				File: file, Line: line, Col: col,
			}}
		}
		return []finding.Finding{{
			RuleID:   "GL007",
			Severity: finding.Error,
			Message: fmt.Sprintf(
				"image %q is controlled entirely by a CI variable — anyone who can set this variable can execute code in an arbitrary container",
				ref,
			),
			File: file, Line: line, Col: col,
		}}
	}

	for _, v := range userControlledImageVars {
		if strings.Contains(ref, "$"+v) || strings.Contains(ref, "${"+v+"}") {
			return []finding.Finding{{
				RuleID:   "GL007",
				Severity: finding.Error,
				Message: fmt.Sprintf(
					"image %q uses user-controlled variable $%s — a commit author can redirect job execution to an arbitrary container tag",
					ref, v,
				),
				File: file, Line: line, Col: col,
			}}
		}
	}
	return nil
}
