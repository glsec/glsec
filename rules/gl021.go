package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl021 struct{}

var GL021 = &gl021{}

func (r *gl021) ID() string { return "GL021" }

var (
	// printCmdRe matches shell output commands.
	printCmdRe = regexp.MustCompile(`\b(?:echo|printf|print)\b`)

	// secretVarRe matches CI variable references whose names end with a secret-indicating suffix.
	secretVarRe = regexp.MustCompile(`\$\{?[A-Za-z_][A-Za-z0-9_]*(?:_TOKEN|_SECRET|_PASSWORD|_PASSWD|_PASS|_PWD|_KEY|_CREDENTIAL|_CERT)\}?`)

	// safeCheckRe matches patterns that reference the variable without printing its value:
	// length checks (-n "$VAR"), default expansions (${VAR:-}, ${VAR:+}), and masked prints.
	safeCheckRe = regexp.MustCompile(`\[\s*(?:-n|-z)\s+|:\-|:\+`)

	// stdinPipeRe matches the safe idiom where an echo/printf is piped into a
	// command reading the secret from stdin (e.g. `echo "$PASS" | docker login
	// --password-stdin`). The value goes to the command's stdin, not the job
	// log — this is the very pattern GL029 recommends.
	stdinPipeRe = regexp.MustCompile(`\|[^|]*--[A-Za-z-]*stdin\b`)
)

func (r *gl021) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"before_script", "script", "after_script"} {
			node := parser.FindKey(job, key)
			if node == nil || node.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range node.Content {
				if item.Kind != yaml.ScalarNode {
					continue
				}
				// Match per physical line: a `|` block scalar is one item but
				// many commands, so an echo on one line must not be paired with
				// a secret on another.
				for i, line := range strings.Split(item.Value, "\n") {
					if !printCmdRe.MatchString(line) {
						continue
					}
					match := secretVarRe.FindString(line)
					if match == "" {
						continue
					}
					// Skip lines that only check the variable's presence, not its value.
					if safeCheckRe.MatchString(line) {
						continue
					}
					// Skip the `echo "$SECRET" | … --password-stdin` idiom.
					if stdinPipeRe.MatchString(line) {
						continue
					}
					findings = append(findings, finding.Finding{
						RuleID:   "GL021",
						Severity: finding.Warn,
						Job:      name.Value,
						Message:  fmt.Sprintf("script prints secret variable %s — value may appear in job logs", match),
						File:     file,
						Line:     item.Line + i,
						Col:      item.Column,
					})
				}
			}
		}
	})

	return findings
}
