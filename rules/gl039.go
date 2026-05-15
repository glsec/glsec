package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl039 struct{}

var GL039 = &gl039{}

func (r *gl039) ID() string { return "GL039" }

// silencedRe matches "|| true" or "|| exit 0" at end of a pipeline segment.
var silencedRe = regexp.MustCompile(`\|\|\s*(?:true|exit\s+0)\b`)

type auditTool struct {
	name string
	re   *regexp.Regexp
}

var auditTools = []auditTool{
	{name: "npm audit", re: regexp.MustCompile(`\bnpm\s+audit\b`)},
	{name: "composer audit", re: regexp.MustCompile(`\bcomposer\s+audit\b`)},
	{name: "trivy", re: regexp.MustCompile(`\btrivy\b`)},
	{name: "grype", re: regexp.MustCompile(`\bgrype\b`)},
	{name: "snyk", re: regexp.MustCompile(`\bsnyk\b`)},
	{name: "osv-scanner", re: regexp.MustCompile(`\bosv-scanner\b`)},
	{name: "retire", re: regexp.MustCompile(`\bretire\b`)},
	{name: "safety check", re: regexp.MustCompile(`\bsafety\s+(?:check|scan)\b`)},
	{name: "anchore-cli", re: regexp.MustCompile(`\banchore-cli\b`)},
	{name: "inspector check", re: regexp.MustCompile(`\binspector\s+check\b`)},
	{name: "syft", re: regexp.MustCompile(`\bsyft\b`)},
}

func (r *gl039) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkAuditSilenced(node, file, "")...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkAuditSilenced(node, file, "")...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				findings = append(findings, checkAuditSilenced(node, file, name.Value)...)
			}
		}
	})

	return findings
}

func checkAuditSilenced(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if !silencedRe.MatchString(item.Value) {
			continue
		}
		for _, tool := range auditTools {
			if tool.re.MatchString(item.Value) {
				findings = append(findings, finding.Finding{
					RuleID:   "GL039",
					Severity: finding.Warn,
					Job:      job,
					Message: fmt.Sprintf(
						"security check %q silenced with \"|| true\" — failures are discarded; use allow_failure: true at job level to keep the signal visible in the pipeline UI",
						tool.name,
					),
					File: file,
					Line: item.Line,
					Col:  item.Column,
				})
				break
			}
		}
	}
	return findings
}
