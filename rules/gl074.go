package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl074 struct{}

var GL074 = &gl074{}

func (r *gl074) ID() string { return "GL074" }

var (
	// gl074CompRe matches a single "$VAR == "lit"" / "$VAR != "lit"" operand.
	gl074CompRe = regexp.MustCompile(`^\$\{?(\w+)\}?\s*(==|!=)\s*["']([^"']*)["']$`)
	// gl074TwoLiteralRe matches a literal-vs-literal comparison ("a" == "b").
	gl074TwoLiteralRe = regexp.MustCompile(`^["']([^"']*)["']\s*(==|!=)\s*["']([^"']*)["']$`)
)

func (r *gl074) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	if wf := parser.FindKey(mapping, "workflow"); wf != nil {
		if rulesNode := parser.FindKey(wf, "rules"); rulesNode != nil {
			findings = append(findings, gl074CheckRules(rulesNode, file, "")...)
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		rulesNode := parser.FindKey(job, "rules")
		if rulesNode == nil {
			return
		}
		for _, f := range gl074CheckRules(rulesNode, file, "") {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func gl074CheckRules(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
			continue
		}
		if reason := tautologyReason(ifNode.Value); reason != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "GL074",
				Severity: finding.Warn,
				Job:      job,
				Message: "rules:if condition is always true (" + reason +
					") — the gate is a no-op; the job runs in every context this rule was meant to restrict",
				File: file,
				Line: ifNode.Line,
				Col:  ifNode.Column,
			})
		}
	}
	return findings
}

// tautologyReason returns a short explanation when cond is provably always true,
// or "" otherwise. It is deliberately conservative: it only reports expressions
// that are true regardless of variable values, to avoid flagging legitimate
// complex conditions.
func tautologyReason(cond string) string {
	operands := strings.Split(cond, "||") // top-level OR; "||" inside quotes is rare

	// An OR is always true if any single operand — not narrowed by && — is
	// itself always true.
	for _, raw := range operands {
		op := stripParens(strings.TrimSpace(raw))
		if strings.Contains(op, "&&") {
			continue
		}
		if op == "true" {
			return `standalone "true" operand`
		}
		if m := gl074TwoLiteralRe.FindStringSubmatch(op); m != nil {
			equal := m[1] == m[3]
			if (m[2] == "==" && equal) || (m[2] == "!=" && !equal) {
				return "constant comparison " + op
			}
		}
	}

	// A || !A: the same variable compared == and != to the same literal across
	// two OR operands covers every possible value.
	type comp struct{ op, lit string }
	byVar := map[string][]comp{}
	for _, raw := range operands {
		op := stripParens(strings.TrimSpace(raw))
		if strings.Contains(op, "&&") {
			continue
		}
		if m := gl074CompRe.FindStringSubmatch(op); m != nil {
			byVar[m[1]] = append(byVar[m[1]], comp{m[2], m[3]})
		}
	}
	for v, comps := range byVar {
		for i := range comps {
			for j := range comps {
				if i != j && comps[i].lit == comps[j].lit && comps[i].op != comps[j].op {
					return "$" + v + ` compared both == and != to "` + comps[i].lit + `"`
				}
			}
		}
	}

	return ""
}

func stripParens(s string) string {
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}
