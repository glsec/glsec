package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl051 struct{}

var GL051 = &gl051{}

func (r *gl051) ID() string { return "GL051" }

func (r *gl051) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)

	unconstrained := gl051UnconstrainedInputs(mapping)
	if len(unconstrained) == 0 {
		return nil
	}

	patterns := make(map[string]*regexp.Regexp, len(unconstrained))
	for _, name := range unconstrained {
		patterns[name] = regexp.MustCompile(`\$\[\[\s*inputs\.` + regexp.QuoteMeta(name) + `\s*\]\]`)
	}

	var findings []finding.Finding

	findings = append(findings, gl051CheckImage(parser.FindKey(mapping, "image"), file, "", patterns)...)
	findings = append(findings, gl051CheckServices(parser.FindKey(mapping, "services"), file, "", patterns)...)
	for _, key := range []string{"before_script", "after_script"} {
		findings = append(findings, gl051CheckScripts(parser.FindKey(mapping, key), file, "", key, patterns)...)
	}

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, gl051CheckImage(parser.FindKey(def, "image"), file, "", patterns)...)
		findings = append(findings, gl051CheckServices(parser.FindKey(def, "services"), file, "", patterns)...)
		for _, key := range []string{"before_script", "after_script"} {
			findings = append(findings, gl051CheckScripts(parser.FindKey(def, key), file, "", key, patterns)...)
		}
	}

	parser.EachJob(doc, func(nameNode *yaml.Node, jobNode *yaml.Node) {
		job := nameNode.Value
		findings = append(findings, gl051CheckImage(parser.FindKey(jobNode, "image"), file, job, patterns)...)
		findings = append(findings, gl051CheckServices(parser.FindKey(jobNode, "services"), file, job, patterns)...)
		for _, key := range []string{"script", "before_script", "after_script"} {
			findings = append(findings, gl051CheckScripts(parser.FindKey(jobNode, key), file, job, key, patterns)...)
		}
		findings = append(findings, gl051CheckEnvironment(parser.FindKey(jobNode, "environment"), file, job, patterns)...)
	})

	return findings
}

// gl051UnconstrainedInputs returns spec:inputs names that have neither a
// regex: constraint nor an options: allowlist.
func gl051UnconstrainedInputs(mapping *yaml.Node) []string {
	spec := parser.FindKey(mapping, "spec")
	if spec == nil {
		return nil
	}
	inputs := parser.FindKey(spec, "inputs")
	if inputs == nil || inputs.Kind != yaml.MappingNode {
		return nil
	}
	var unconstrained []string
	for i := 0; i+1 < len(inputs.Content); i += 2 {
		name := inputs.Content[i].Value
		def := inputs.Content[i+1]
		if def.Kind != yaml.MappingNode {
			unconstrained = append(unconstrained, name)
			continue
		}
		if parser.FindKey(def, "regex") == nil && parser.FindKey(def, "options") == nil {
			unconstrained = append(unconstrained, name)
		}
	}
	return unconstrained
}

func gl051CheckScalar(node *yaml.Node, file, job, keyword string, patterns map[string]*regexp.Regexp) []finding.Finding {
	if node == nil || node.Kind != yaml.ScalarNode {
		return nil
	}
	var findings []finding.Finding
	for inputName, re := range patterns {
		if re.MatchString(node.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL051",
				Severity: finding.Warn,
				Job:      job,
				Message:  fmt.Sprintf("unconstrained spec:inputs entry %q interpolated into %s — add regex: or options: to restrict caller-supplied values", inputName, keyword),
				File:     file,
				Line:     node.Line,
				Col:      node.Column,
			})
		}
	}
	return findings
}

func gl051CheckImage(node *yaml.Node, file, job string, patterns map[string]*regexp.Regexp) []finding.Finding {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return gl051CheckScalar(node, file, job, "image:", patterns)
	case yaml.MappingNode:
		return gl051CheckScalar(parser.FindKey(node, "name"), file, job, "image:", patterns)
	}
	return nil
}

func gl051CheckServices(node *yaml.Node, file, job string, patterns map[string]*regexp.Regexp) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			findings = append(findings, gl051CheckScalar(item, file, job, "services:", patterns)...)
		case yaml.MappingNode:
			findings = append(findings, gl051CheckScalar(parser.FindKey(item, "name"), file, job, "services:", patterns)...)
		}
	}
	return findings
}

func gl051CheckScripts(node *yaml.Node, file, job, keyword string, patterns map[string]*regexp.Regexp) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		findings = append(findings, gl051CheckScalar(item, file, job, keyword+":", patterns)...)
	}
	return findings
}

func gl051CheckEnvironment(node *yaml.Node, file, job string, patterns map[string]*regexp.Regexp) []finding.Finding {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return gl051CheckScalar(node, file, job, "environment:name:", patterns)
	case yaml.MappingNode:
		return gl051CheckScalar(parser.FindKey(node, "name"), file, job, "environment:name:", patterns)
	}
	return nil
}
