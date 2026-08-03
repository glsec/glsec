package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl082 struct{}

var GL082 = &gl082{}

func (r *gl082) ID() string { return "GL082" }

// scanDisableVars maps each CI/CD variable that switches off a GitLab-managed
// security scan to the scan it disables. Every managed template gates its jobs
// on `rules: - if: $VAR == 'true' || $VAR == '1' → when: never`, so setting one
// of these removes the scan from the pipeline entirely — no job, no report, and
// nothing for the allow_failure check in GL008 to look at.
var scanDisableVars = map[string]string{
	"SAST_DISABLED":                "SAST",
	"SECRET_DETECTION_DISABLED":    "secret detection",
	"CONTAINER_SCANNING_DISABLED":  "container scanning",
	"DEPENDENCY_SCANNING_DISABLED": "dependency scanning",
	"DAST_DISABLED":                "DAST",
	"COVFUZZ_DISABLED":             "coverage-guided fuzzing",
	"API_FUZZING_DISABLED":         "API fuzzing",
	"DAST_API_DISABLED":            "DAST API",
}

// dastDefaultBranchVar disables DAST on the default branch only, so it gets its
// own message.
const dastDefaultBranchVar = "DAST_DISABLED_FOR_DEFAULT_BRANCH"

func (r *gl082) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, r.checkVariables(parser.FindKey(mapping, "variables"), file)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, r.checkVariables(parser.FindKey(def, "variables"), file)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range r.checkVariables(parser.FindKey(job, "variables"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func (r *gl082) checkVariables(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		scan, known := scanDisableVars[key]
		if !known && key != dastDefaultBranchVar {
			continue
		}

		scalar := analyzerScalar(node.Content[i+1])
		if scalar == nil || !disablesScan(scalar) {
			continue
		}

		msg := fmt.Sprintf(
			"%s turns off managed %s — the template gates its jobs on this variable, so nothing scans and no report is produced; remove it, or narrow the exception and document why",
			key, scan,
		)
		if key == dastDefaultBranchVar {
			msg = fmt.Sprintf(
				"%s turns off managed DAST on the default branch — the branch that ships is the one left unscanned; remove it, or narrow the exception and document why",
				key,
			)
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL082",
			Severity: finding.Warn,
			Message:  msg,
			File:     file,
			Line:     scalar.Line,
			Col:      scalar.Column,
		})
	}
	return findings
}

// disablesScan reports whether a variable value actually satisfies the
// templates' `$VAR == 'true' || $VAR == '1'` gate. That comparison is against
// strings and is case-sensitive, so a quoted "True" does not disable anything —
// but an unquoted YAML boolean does, in any spelling, because GitLab stringifies
// it to "true" before the rule is evaluated.
func disablesScan(n *yaml.Node) bool {
	if n.Tag == "!!bool" {
		return strings.EqualFold(n.Value, "true")
	}
	return n.Value == "true" || n.Value == "1"
}
