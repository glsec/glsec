package rules

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl009 struct{}

var GL009 = &gl009{}

func (r *gl009) ID() string { return "GL009" }

func (r *gl009) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		idTokens := parser.FindKey(job, "id_tokens")
		if idTokens == nil || idTokens.Kind != yaml.MappingNode {
			return
		}
		// Each key is a token name, each value is a mapping with an aud: key.
		for i := 0; i+1 < len(idTokens.Content); i += 2 {
			tokenDef := idTokens.Content[i+1]
			if tokenDef.Kind != yaml.MappingNode {
				continue
			}
			audNode := parser.FindKey(tokenDef, "aud")
			if audNode == nil {
				continue
			}
			findings = append(findings, checkAudNode(audNode, file)...)
		}
	})

	return findings
}

func checkAudNode(node *yaml.Node, file string) []finding.Finding {
	switch node.Kind {
	case yaml.ScalarNode:
		if isOverbroad(node.Value) {
			return []finding.Finding{overbroad(node.Value, node.Line, node.Column, file)}
		}
	case yaml.SequenceNode:
		var findings []finding.Finding
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode && isOverbroad(item.Value) {
				findings = append(findings, overbroad(item.Value, item.Line, item.Column, file))
			}
		}
		return findings
	}
	return nil
}

// isOverbroad returns true when the audience is a GitLab instance root URL.
// Such an audience accepts OIDC tokens from any project on that instance,
// rather than being scoped to a specific cloud service.
func isOverbroad(aud string) bool {
	u, err := url.Parse(aud)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.Contains(strings.ToLower(u.Hostname()), "gitlab")
}

func overbroad(aud string, line, col int, file string) finding.Finding {
	return finding.Finding{
		RuleID:   "GL009",
		Severity: finding.Warn,
		Message: fmt.Sprintf(
			"id_token audience %q is a GitLab instance URL — use a service-specific audience (e.g. https://sts.amazonaws.com) to limit token acceptance to the intended cloud service",
			aud,
		),
		File: file,
		Line: line,
		Col:  col,
	}
}
