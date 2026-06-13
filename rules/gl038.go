package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl038 struct{}

var GL038 = &gl038{}

func (r *gl038) ID() string { return "GL038" }

type credCheck struct {
	tool string
	re   *regexp.Regexp
	msg  string
}

var credChecks = []credCheck{
	{
		tool: "sqlcmd",
		re:   regexp.MustCompile(`\bsqlcmd\b.*-P\s+["']?[^$"'\s]`),
		msg:  "script passes hardcoded credential to sqlcmd via -P flag — use a masked CI variable instead",
	},
	{
		tool: "mysql",
		re:   regexp.MustCompile(`\bmysql(?:dump|pump)?\b.*\s-p[A-Za-z0-9!@#%^&*()\[\]{}<>]`),
		msg:  "script passes hardcoded credential to mysql via -p flag — use a masked CI variable instead",
	},
	{
		tool: "mysql",
		re:   regexp.MustCompile(`\bmysql(?:dump|pump)?\b.*--password=[^$'"\s]`),
		msg:  "script passes hardcoded credential to mysql via --password flag — use a masked CI variable instead",
	},
	{
		tool: "psql/PGPASSWORD",
		re:   regexp.MustCompile(`PGPASSWORD=[^$'"\s]`),
		msg:  "script passes hardcoded credential via PGPASSWORD — use a masked CI variable instead",
	},
	{
		tool: "mongosh",
		re:   regexp.MustCompile(`\bmongo(?:sh|dump|restore|import|export)?\b.*--password\s+[^$\s"']`),
		msg:  "script passes hardcoded credential via --password flag — use a masked CI variable instead",
	},
	{
		tool: "sed",
		re:   regexp.MustCompile(`\bsed\b.+s/[^/]+/[^/:]*:[^$][^@]*@/`),
		msg:  "script rewrites URL with hardcoded password literal via sed — use a masked CI variable instead",
	},
}

func (r *gl038) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkHardcodedCredScript(node, file, job)...)
	})
	return findings
}

func checkHardcodedCredScript(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		for _, check := range credChecks {
			if check.re.MatchString(item.Value) {
				findings = append(findings, finding.Finding{
					RuleID:   "GL038",
					Severity: finding.Error,
					Job:      job,
					Message:  fmt.Sprintf("[%s] %s", check.tool, check.msg),
					File:     file,
					Line:     item.Line,
					Col:      item.Column,
				})
				break
			}
		}
	}
	return findings
}
