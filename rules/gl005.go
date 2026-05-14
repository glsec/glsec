package rules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl005 struct{}

var GL005 = &gl005{}

func (r *gl005) ID() string { return "GL005" }

// sensitivePatterns are glob patterns matching files that commonly contain secrets.
var sensitivePatterns = []string{
	".env", ".env.*",
	"*.pem", "*.key", "*.p12", "*.pfx", "*.der",
	"*.keystore", "*.jks",
	"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
	"*.secret", "*secret*",
	"*credential*", "*credentials*",
	"*password*", "*passwd*",
	"*.token",
	"kubeconfig", "*.kubeconfig",
	"*.tfstate", "*.tfvars",
}

func (r *gl005) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		artifactsNode := parser.FindKey(job, "artifacts")
		if artifactsNode == nil {
			return
		}
		findings = append(findings, checkArtifacts(artifactsNode, file)...)
	})

	return findings
}

func checkArtifacts(node *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	pathsNode := parser.FindKey(node, "paths")
	if pathsNode != nil && pathsNode.Kind == yaml.SequenceNode {
		for _, item := range pathsNode.Content {
			if item.Kind != yaml.ScalarNode {
				continue
			}
			if pat := matchesSensitivePattern(item.Value); pat != "" {
				findings = append(findings, finding.Finding{
					RuleID:   "GL005",
					Severity: finding.Error,
					Message:  fmt.Sprintf("artifact path %q matches sensitive file pattern %q — exclude secrets from artifacts", item.Value, pat),
					File:     file,
					Line:     item.Line,
					Col:      item.Column,
				})
			}
		}
	}

	_, expireNode := parser.FindKeyNode(node, "expire_in")
	if expireNode == nil {
		findings = append(findings, finding.Finding{
			RuleID:   "GL005",
			Severity: finding.Warn,
			Message:  "artifacts block has no \"expire_in\" — artifacts are stored indefinitely, increasing the exposure window for any sensitive content",
			File:     file,
			Line:     node.Line,
			Col:      node.Column,
		})
	}

	return findings
}

func matchesSensitivePattern(path string) string {
	base := filepath.Base(path)
	// also check the full path for patterns like "*secret*"
	targets := []string{base, strings.ToLower(base), strings.ToLower(path)}

	for _, pat := range sensitivePatterns {
		for _, target := range targets {
			if ok, _ := filepath.Match(pat, target); ok {
				return pat
			}
		}
	}
	return ""
}
