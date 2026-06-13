package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl072 struct{}

var GL072 = &gl072{}

func (r *gl072) ID() string { return "GL072" }

// refVarRe matches a CI/CD variable reference ($VAR or ${VAR}) inside a ref.
var refVarRe = regexp.MustCompile(`\$\{?[A-Za-z_]`)

func (r *gl072) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		needs := parser.FindKey(job, "needs")
		if needs == nil || needs.Kind != yaml.SequenceNode {
			return
		}
		for _, item := range needs.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			project := parser.FindKey(item, "project")
			if project == nil {
				continue // plain needs: or needs:pipeline: — out of scope
			}
			if artifactsDisabled(item) {
				continue // no artifact download → no poisoning risk
			}
			refNode := parser.FindKey(item, "ref")
			if refNode == nil || refNode.Kind != yaml.ScalarNode {
				continue
			}
			if f := checkNeedsRef(project, refNode, file); f != nil {
				f.Job = name.Value
				findings = append(findings, *f)
			}
		}
	})

	return findings
}

func checkNeedsRef(project, refNode *yaml.Node, file string) *finding.Finding {
	if refVarRe.MatchString(refNode.Value) {
		return &finding.Finding{
			RuleID:   "GL072",
			Severity: finding.Warn,
			Message: fmt.Sprintf(
				"cross-project artifact download from %q uses a variable ref %q — the artifact source is chosen at pipeline time; pin ref: to a commit SHA or release tag",
				project.Value, refNode.Value,
			),
			File: file,
			Line: refNode.Line,
			Col:  refNode.Column,
		}
	}
	if isMutableRef(refNode.Value) {
		return &finding.Finding{
			RuleID:   "GL072",
			Severity: finding.Warn,
			Message: fmt.Sprintf(
				"cross-project artifact download from %q uses mutable ref %q — anyone who can push to that ref controls the consumed artifacts; pin ref: to a commit SHA or release tag",
				project.Value, refNode.Value,
			),
			File: file,
			Line: refNode.Line,
			Col:  refNode.Column,
		}
	}
	return nil
}

// artifactsDisabled reports whether the needs entry explicitly sets
// artifacts: false. Absent defaults to true (artifacts are downloaded).
func artifactsDisabled(item *yaml.Node) bool {
	a := parser.FindKey(item, "artifacts")
	return a != nil && a.Kind == yaml.ScalarNode && a.Value == "false"
}
