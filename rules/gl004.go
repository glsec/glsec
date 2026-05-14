package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl004 struct{}

var GL004 = &gl004{}

func (r *gl004) ID() string { return "GL004" }

var (
	jobTokenPattern = regexp.MustCompile(`\$\{?CI_JOB_TOKEN\}?`)
	// urlPattern captures the full URL and its domain separately.
	urlPattern004 = regexp.MustCompile(`https?://([a-zA-Z0-9.\-]+)`)
)

func (r *gl004) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, scanScriptForToken(node, file)...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, scanScriptForToken(node, file)...)
			}
		}
	}

	parser.EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				findings = append(findings, scanScriptForToken(node, file)...)
			}
		}
	})

	return findings
}

func scanScriptForToken(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			findings = append(findings, checkTokenLine(item, file)...)
		}
	}
	return findings
}

func checkTokenLine(node *yaml.Node, file string) []finding.Finding {
	if !jobTokenPattern.MatchString(node.Value) {
		return nil
	}

	// Only flag when an explicit non-GitLab URL is present in the same command.
	// If no URL is found the token might be going to $CI_SERVER_URL or similar — skip.
	matches := urlPattern004.FindAllStringSubmatch(node.Value, -1)
	for _, m := range matches {
		domain := m[1]
		if !isGitLabDomain(domain) {
			return []finding.Finding{{
				RuleID:   "GL004",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"CI_JOB_TOKEN sent to non-GitLab host %q — this token is scoped to the GitLab API and should not be forwarded to external services",
					domain,
				),
				File: file,
				Line: node.Line,
				Col:  node.Column,
			}}
		}
	}
	return nil
}

func isGitLabDomain(domain string) bool {
	return domain == "gitlab.com" || strings.HasSuffix(domain, ".gitlab.com")
}
