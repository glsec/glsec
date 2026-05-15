package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl011 struct{}

var GL011 = &gl011{}

func (r *gl011) ID() string { return "GL011" }

var (
	// downloadToolRe matches curl or wget anywhere in a script line.
	downloadToolRe = regexp.MustCompile(`\b(?:curl|wget)\b`)
	// pipeToShellRe matches a pipe directly into a shell interpreter.
	pipeToShellRe = regexp.MustCompile(`\|\s*(?:bash|sh|python[23]?|ruby|perl|node)\b`)
	// processSubstRe matches bash process substitution: <(curl ...) or <(wget ...).
	processSubstRe = regexp.MustCompile(`<\s*\(\s*(?:curl|wget)\b`)
)

func (r *gl011) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkScriptDownloadExecute(node, file)...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkScriptDownloadExecute(node, file)...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				for _, f := range checkScriptDownloadExecute(node, file) {
					f.Job = name.Value
					findings = append(findings, f)
				}
			}
		}
	})

	return findings
}

func checkScriptDownloadExecute(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if isDownloadExecute(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL011",
				Severity: finding.Error,
				Message:  fmt.Sprintf("script line downloads and executes remote code without integrity verification: %q", truncate(item.Value, 80)),
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}

func isDownloadExecute(line string) bool {
	if processSubstRe.MatchString(line) {
		return true
	}
	return downloadToolRe.MatchString(line) && pipeToShellRe.MatchString(line)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
