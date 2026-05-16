package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl002 struct{}

var GL002 = &gl002{}

func (r *gl002) ID() string { return "GL002" }

// userControlledVars are GitLab CI predefined variables whose values are
// set by external actors (commit authors, MR creators) and can contain
// shell metacharacters like $(...) or `...`.
var userControlledVars = []string{
	"CI_COMMIT_REF_NAME",
	"CI_COMMIT_BRANCH",
	"CI_COMMIT_TAG",
	"CI_COMMIT_TITLE",
	"CI_COMMIT_MESSAGE",
	"CI_COMMIT_DESCRIPTION",
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"CI_MERGE_REQUEST_TITLE",
	"CI_MERGE_REQUEST_DESCRIPTION",
	"CI_PIPELINE_NAME",
}

// userVarRe matches any user-controlled variable reference ($VAR or ${VAR})
// followed by a word boundary so that e.g. $CI_COMMIT_REF_NAME_EXTRA is not matched.
var userVarRe = regexp.MustCompile(
	`\$\{?(` + strings.Join(userControlledVars, "|") + `)\b`,
)

func (r *gl002) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	// top-level and default script blocks
	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkScriptNode(node, file)...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkScriptNode(node, file)...)
			}
		}
	}

	// per-job script blocks
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				for _, f := range checkScriptNode(node, file) {
					f.Job = name.Value
					findings = append(findings, f)
				}
			}
		}
	})

	return findings
}

func checkScriptNode(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			findings = append(findings, checkScriptLine(item, file)...)
		}
	}
	return findings
}

func checkScriptLine(node *yaml.Node, file string) []finding.Finding {
	masked := maskShellQuotes(node.Value)
	matches := userVarRe.FindAllStringSubmatch(masked, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var findings []finding.Finding
	for _, m := range matches {
		varName := m[1]
		if seen[varName] {
			continue
		}
		seen[varName] = true
		findings = append(findings, finding.Finding{
			RuleID:   "GL002",
			Severity: finding.Warn,
			Message: fmt.Sprintf(
				"unquoted user-controlled variable $%s in script — value is set by commit authors and may contain shell metacharacters",
				varName,
			),
			File: file,
			Line: node.Line,
			Col:  node.Column,
		})
	}
	return findings
}

// maskShellQuotes replaces the contents of single- and double-quoted shell
// strings with spaces. Variable references inside either quote type are safe
// from word splitting and should not be flagged; masking them makes the
// caller's regex only see genuinely unquoted occurrences.
//
// Backslash escapes outside quotes are also masked (two spaces replace the
// pair) because \$VAR is not a variable reference.
func maskShellQuotes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			b.WriteByte(' ')
			b.WriteByte(' ')
			i += 2
		case s[i] == '\'':
			b.WriteByte('\'')
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(' ')
				i++
			}
			if i < len(s) {
				b.WriteByte('\'')
				i++
			}
		case s[i] == '"':
			b.WriteByte('"')
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(' ')
					b.WriteByte(' ')
					i += 2
					continue
				}
				b.WriteByte(' ')
				i++
			}
			if i < len(s) {
				b.WriteByte('"')
				i++
			}
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}
