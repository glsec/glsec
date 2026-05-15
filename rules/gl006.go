package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl006 struct{}

var GL006 = &gl006{}

func (r *gl006) ID() string { return "GL006" }

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"GitLab PAT", regexp.MustCompile(`^glpat-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab CI job token", regexp.MustCompile(`^glcbt-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab runner registration token", regexp.MustCompile(`^glrt-[A-Za-z0-9_-]{20,}$`)},
	{"GitLab deploy token", regexp.MustCompile(`^gldt-[A-Za-z0-9_-]{20,}$`)},
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"PEM private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY`)},
	{"GitHub PAT", regexp.MustCompile(`^ghp_[A-Za-z0-9]{36,}$`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{82,}$`)},
	{"Slack token", regexp.MustCompile(`^xox[baprs]-[A-Za-z0-9-]{10,}$`)},
	{"OpenAI API key", regexp.MustCompile(`^sk-[A-Za-z0-9]{32,}$`)},
}

func (r *gl006) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, checkVariablesNode(parser.FindKey(mapping, "variables"), file)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkVariablesNode(parser.FindKey(def, "variables"), file)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range checkVariablesNode(parser.FindKey(job, "variables"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func checkVariablesNode(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		varName := node.Content[i].Value
		val := node.Content[i+1]

		var scalar *yaml.Node
		switch val.Kind {
		case yaml.ScalarNode:
			scalar = val
		case yaml.MappingNode:
			// Extended form: {value: ..., description: ...}
			if v := parser.FindKey(val, "value"); v != nil && v.Kind == yaml.ScalarNode {
				scalar = v
			}
		}
		if scalar == nil {
			continue
		}
		if f := checkSecretValue(scalar, varName, file); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

func checkSecretValue(node *yaml.Node, varName, file string) *finding.Finding {
	v := node.Value
	if v == "" || strings.HasPrefix(v, "$") {
		return nil
	}
	for _, pat := range secretPatterns {
		if pat.re.MatchString(v) {
			f := finding.Finding{
				RuleID:   "GL006",
				Severity: finding.Error,
				Message: fmt.Sprintf(
					"variable %q appears to contain a hardcoded %s — use GitLab CI/CD masked variables (Settings → CI/CD → Variables) instead",
					varName, pat.name,
				),
				File: file,
				Line: node.Line,
				Col:  node.Column,
			}
			return &f
		}
	}
	return nil
}
