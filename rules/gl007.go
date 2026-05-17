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

	findings = append(findings, checkImageVarInjection(parser.FindKey(mapping, "image"), file)...)
	findings = append(findings, checkServicesVarInjection(parser.FindKey(mapping, "services"), file)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkImageVarInjection(parser.FindKey(def, "image"), file)...)
		findings = append(findings, checkServicesVarInjection(parser.FindKey(def, "services"), file)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range checkImageVarInjection(parser.FindKey(job, "image"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
		for _, f := range checkServicesVarInjection(parser.FindKey(job, "services"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func checkImageVarInjection(node *yaml.Node, file string) []finding.Finding {
	if node == nil {
		return nil
	}
	ref, line, col := imageRef(node)
	if ref == "" {
		return nil
	}
	return imageVarFindings(ref, line, col, file)
}

func checkServicesVarInjection(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		ref, line, col := imageRef(item)
		if ref == "" {
			continue
		}
		findings = append(findings, imageVarFindings(ref, line, col, file)...)
	}
	return findings
}

func imageVarFindings(ref string, line, col int, file string) []finding.Finding {
	if entireVarRe.MatchString(ref) {
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
