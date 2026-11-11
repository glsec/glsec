// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl007 struct{}

var GL007 = &gl007{}

func (r *gl007) ID() string { return "GL007" }

// entireVarRe matches an image ref that is entirely a single variable reference.
var entireVarRe = mustCompilePrefiltered(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`)

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

	findings = append(findings, checkImageVarInjection(parser.FindKey(mapping, "image"), file, globalVars, nil, nil)...)
	findings = append(findings, checkServicesVarInjection(parser.FindKey(mapping, "services"), file, globalVars, nil, nil)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkImageVarInjection(parser.FindKey(def, "image"), file, globalVars, nil, nil)...)
		findings = append(findings, checkServicesVarInjection(parser.FindKey(def, "services"), file, globalVars, nil, nil)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		jobVars := parser.FindKey(job, "variables")
		for _, f := range checkImageVarInjection(parser.FindKey(job, "image"), file, globalVars, jobVars, job) {
			f.Job = name.Value
			findings = append(findings, f)
		}
		for _, f := range checkServicesVarInjection(parser.FindKey(job, "services"), file, globalVars, jobVars, job) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

// imageVarInFileLiteral reports whether a whole-variable image ref ($IMG) names
// a variable this file defines to an image literal: a plain value, a value that
// only interpolates other in-file literals, or a complete parallel:matrix list
// of such values. A value that still names an external or undefined variable
// does not count, because it isn't resolvable to an image here.
func imageVarInFileLiteral(ref string, globalVars, jobVars, job *yaml.Node) bool {
	name := strings.Trim(ref, "${}")
	return imageVarResolvesLiteral(name, globalVars, jobVars, job, map[string]bool{})
}

func imageVarResolvesLiteral(name string, globalVars, jobVars, job *yaml.Node, seen map[string]bool) bool {
	if seen[name] {
		return false
	}
	seen[name] = true
	vals := inFileImageVarValues(name, globalVars, jobVars, job)
	if len(vals) == 0 {
		return false
	}
	for _, val := range vals {
		next := map[string]bool{}
		for k, v := range seen {
			next[k] = v
		}
		if !imageValueIsInFileLiteral(val, globalVars, jobVars, job, next) {
			return false
		}
	}
	return true
}

// inFileImageVarValues collects the values this file assigns to name: the
// job's own variables:, else the top-level variables:, plus any
// parallel:matrix entries. When the matrix sets name on every entry and the
// job does not also define it, the matrix list is the whole value.
func inFileImageVarValues(name string, globalVars, jobVars, job *yaml.Node) []string {
	jobVals := varValues(jobVars, name)
	globalVals := varValues(globalVars, name)
	vals := jobVals
	if len(vals) == 0 {
		vals = append(vals, globalVals...)
	}
	if job != nil {
		mv, complete := matrixValues(job, name)
		if len(mv) > 0 {
			if complete && len(jobVals) == 0 {
				return mv
			}
			vals = append(append([]string{}, mv...), vals...)
		}
	}
	return vals
}

func imageValueIsInFileLiteral(val string, globalVars, jobVars, job *yaml.Node, seen map[string]bool) bool {
	if val == "" {
		return false
	}
	names := ciVarNames(val)
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if !imageVarResolvesLiteral(n, globalVars, jobVars, job, seen) {
			return false
		}
	}
	return true
}

// ciVarNames returns the CI variable names interpolated in s ($VAR or ${VAR}).
func ciVarNames(s string) []string {
	var names []string
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			j := i + 2
			k := j
			for k < len(s) && (s[k] == '_' || s[k] >= 'A' && s[k] <= 'Z' || s[k] >= 'a' && s[k] <= 'z' || k > j && s[k] >= '0' && s[k] <= '9') {
				k++
			}
			if k > j && k < len(s) && s[k] == '}' {
				names = append(names, s[j:k])
			}
			i = k
			continue
		}
		if i+1 < len(s) && (s[i+1] == '_' || s[i+1] >= 'A' && s[i+1] <= 'Z' || s[i+1] >= 'a' && s[i+1] <= 'z') {
			k := i + 2
			for k < len(s) && (s[k] == '_' || s[k] >= 'A' && s[k] <= 'Z' || s[k] >= 'a' && s[k] <= 'z' || s[k] >= '0' && s[k] <= '9') {
				k++
			}
			names = append(names, s[i+1:k])
			i = k - 1
		}
	}
	return names
}

func checkImageVarInjection(node *yaml.Node, file string, globalVars, jobVars, job *yaml.Node) []finding.Finding {
	if node == nil {
		return nil
	}
	ref, line, col := imageRef(node)
	if ref == "" {
		return nil
	}
	return imageVarFindings(ref, line, col, file, globalVars, jobVars, job)
}

func checkServicesVarInjection(node *yaml.Node, file string, globalVars, jobVars, job *yaml.Node) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		ref, line, col := imageRef(item)
		if ref == "" {
			continue
		}
		findings = append(findings, imageVarFindings(ref, line, col, file, globalVars, jobVars, job)...)
	}
	return findings
}

func imageVarFindings(ref string, line, col int, file string, globalVars, jobVars, job *yaml.Node) []finding.Finding {
	if entireVarRe.MatchString(ref) {
		if imageVarInFileLiteral(ref, globalVars, jobVars, job) {
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
