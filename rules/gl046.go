package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl046 struct{}

var GL046 = &gl046{}

func (r *gl046) ID() string { return "GL046" }

// cacheKeyVars extends the GL002 user-controlled variable set with CI_COMMIT_REF_SLUG,
// which is a normalised form of CI_COMMIT_REF_NAME and carries the same cache-poisoning risk.
var cacheKeyVars = append(append([]string{}, userControlledVars...), "CI_COMMIT_REF_SLUG")

var cacheKeyVarRe = regexp.MustCompile(
	`\$\{?(` + strings.Join(cacheKeyVars, "|") + `)\b`,
)

func (r *gl046) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkCacheNode(parser.FindKey(def, "cache"), file, "")...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range checkCacheNode(parser.FindKey(job, "cache"), file, "") {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func checkCacheNode(node *yaml.Node, file, job string) []finding.Finding {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.MappingNode:
		return checkCacheMapping(node, file, job)
	case yaml.SequenceNode:
		var findings []finding.Finding
		for _, item := range node.Content {
			if item.Kind == yaml.MappingNode {
				findings = append(findings, checkCacheMapping(item, file, job)...)
			}
		}
		return findings
	}
	return nil
}

func checkCacheMapping(node *yaml.Node, file, job string) []finding.Finding {
	keyNode := parser.FindKey(node, "key")
	if keyNode == nil {
		return nil
	}

	switch keyNode.Kind {
	case yaml.ScalarNode:
		if m := cacheKeyVarRe.FindStringSubmatch(keyNode.Value); m != nil {
			return []finding.Finding{{
				RuleID:   "GL046",
				Severity: finding.Warn,
				Job:      job,
				Message: fmt.Sprintf(
					"cache key contains user-controlled variable $%s — an attacker can craft a branch name to collide with the cache key of a protected pipeline and inject malicious build artefacts",
					m[1],
				),
				File: file,
				Line: keyNode.Line,
				Col:  keyNode.Column,
			}}
		}
	case yaml.MappingNode:
		prefixNode := parser.FindKey(keyNode, "prefix")
		if prefixNode != nil && prefixNode.Kind == yaml.ScalarNode {
			if m := cacheKeyVarRe.FindStringSubmatch(prefixNode.Value); m != nil {
				return []finding.Finding{{
					RuleID:   "GL046",
					Severity: finding.Warn,
					Job:      job,
					Message: fmt.Sprintf(
						"cache key prefix contains user-controlled variable $%s — an attacker can craft a branch name to collide with the cache key of a protected pipeline and inject malicious build artefacts",
						m[1],
					),
					File: file,
					Line: prefixNode.Line,
					Col:  prefixNode.Column,
				}}
			}
		}
	}
	return nil
}
