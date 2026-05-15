package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl002 struct{}

var GL002 = &gl002{}

func (r *gl002) ID() string { return "GL002" }

// userControlledVars are GitLab CI predefined variables whose values are
// set by external actors (commit authors, MR creators) and can contain
// shell metacharacters like $(...) or `...`.
var userControlledVars = []string{
	"CI_COMMIT_REF_NAME",
	"CI_COMMIT_TITLE",
	"CI_COMMIT_MESSAGE",
	"CI_COMMIT_DESCRIPTION",
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"CI_MERGE_REQUEST_TITLE",
	"CI_MERGE_REQUEST_DESCRIPTION",
	"CI_PIPELINE_NAME",
}

// unquotedVarPatterns matches $VAR or ${VAR} not immediately preceded by '"'.
// Using '"' as the only safe predecessor keeps the heuristic simple:
// "$VAR" is the idiomatic safe form; anything else (unquoted args, assignments,
// subshells) is potentially exploitable.
var unquotedVarPatterns = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(userControlledVars))
	for i, v := range userControlledVars {
		out[i] = regexp.MustCompile(`(?:^|[^"])\$\{?` + regexp.QuoteMeta(v) + `\}?`)
	}
	return out
}()

func (r *gl002) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	// top-level and default script blocks
	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkScriptNode(node, file)...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkScriptNode(node, file)...)
			}
		}
	}

	// per-job script blocks
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				for _, f := range checkScriptNode(node, file) {
					f.Job = name.Value
					findings = append(findings, f)
				}
			}
		}
	})

	return findings
}

func checkScriptNode(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		findings = append(findings, checkScriptLine(item, file)...)
	}
	return findings
}

func checkScriptLine(node *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	for i, pat := range unquotedVarPatterns {
		if pat.MatchString(node.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL002",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"unquoted user-controlled variable $%s in script — value is set by commit authors and may contain shell metacharacters",
					userControlledVars[i],
				),
				File: file,
				Line: node.Line,
				Col:  node.Column,
			})
		}
	}
	return findings
}
