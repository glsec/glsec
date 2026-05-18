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
	mapping := parser.Unwrap(doc)

	if def := parser.FindKey(mapping, "default"); def != nil {
		if artifactsNode := parser.FindKey(def, "artifacts"); artifactsNode != nil {
			findings = append(findings, checkArtifacts(artifactsNode, file)...)
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		artifactsNode := parser.FindKey(job, "artifacts")
		if artifactsNode == nil {
			return
		}
		for _, f := range checkArtifacts(artifactsNode, file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func checkArtifacts(node *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	for _, section := range []string{"paths", "exclude"} {
		seqNode := parser.FindKey(node, section)
		if seqNode == nil || seqNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range seqNode.Content {
			if item.Kind != yaml.ScalarNode {
				continue
			}
			findings = append(findings, checkArtifactPath(item, file)...)
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

func checkArtifactPath(item *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	path := item.Value

	switch {
	case strings.HasPrefix(path, "/"):
		findings = append(findings, finding.Finding{
			RuleID:   "GL005",
			Severity: finding.Error,
			Message:  fmt.Sprintf("artifact path %q is an absolute path — references the host filesystem directly and can exfiltrate arbitrary files on shell executors", path),
			File:     file,
			Line:     item.Line,
			Col:      item.Column,
		})
	case strings.Contains(path, "../"):
		findings = append(findings, finding.Finding{
			RuleID:   "GL005",
			Severity: finding.Error,
			Message:  fmt.Sprintf("artifact path %q contains path traversal — can escape the project directory on shell executors", path),
			File:     file,
			Line:     item.Line,
			Col:      item.Column,
		})
	default:
		if pat := matchesSensitivePattern(path); pat != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "GL005",
				Severity: finding.Error,
				Message:  fmt.Sprintf("artifact path %q matches sensitive file pattern %q — exclude secrets from artifacts", path, pat),
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
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
