package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
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
	"CI_COMMIT_TAG_MESSAGE",
	"CI_COMMIT_TITLE",
	"CI_COMMIT_MESSAGE",
	"CI_COMMIT_DESCRIPTION",
	"CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
	"CI_MERGE_REQUEST_TITLE",
	"CI_MERGE_REQUEST_DESCRIPTION",
	"CI_PIPELINE_NAME",
	// Identity variables controlled directly by an untrusted contributor via
	// the commit or their own account profile. In fork MR pipelines these
	// reflect the external MR author. CI_COMMIT_AUTHOR is "Name <email>" taken
	// verbatim from the commit; GITLAB_USER_NAME/EMAIL are user-editable.
	// GITLAB_USER_LOGIN is deliberately excluded — its charset is restricted.
	"CI_COMMIT_AUTHOR",
	"GITLAB_USER_NAME",
	"GITLAB_USER_EMAIL",
}

// userVarRe matches any user-controlled variable reference ($VAR or ${VAR})
// followed by a word boundary so that e.g. $CI_COMMIT_REF_NAME_EXTRA is not matched.
var userVarRe = regexp.MustCompile(
	`\$\{?(` + strings.Join(userControlledVars, "|") + `)\b`,
)

func (r *gl002) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		for _, f := range checkScriptNode(node, file) {
			f.Job = job
			findings = append(findings, f)
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
	matches := userVarRe.FindAllStringSubmatchIndex(masked, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var findings []finding.Finding
	for _, loc := range matches {
		dollarPos := loc[0]
		varName := masked[loc[2]:loc[3]]
		if seen[varName] {
			continue
		}
		if isBareAssignment(masked, dollarPos) {
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

// isBareAssignment reports whether the $ at dollarPos in s is the RHS of a
// simple shell assignment (IDENTIFIER=$VAR). The LHS must consist solely of
// a valid identifier followed by '=', with nothing else on the line before it.
// The RHS of such an assignment is not word-split by the shell, so it is not
// subject to injection via metacharacters.
func isBareAssignment(s string, dollarPos int) bool {
	if dollarPos == 0 {
		return false
	}
	if s[dollarPos-1] != '=' {
		return false
	}
	lhs := s[:dollarPos-1]
	if len(lhs) == 0 {
		return false
	}
	for _, ch := range lhs {
		if (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}
	// first char must not be a digit
	return lhs[0] < '0' || lhs[0] > '9'
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
