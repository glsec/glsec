package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl042 struct{}

var GL042 = &gl042{}

func (r *gl042) ID() string { return "GL042" }

type tlsCheck struct {
	tool string
	re   *regexp.Regexp
	msg  string
}

var tlsChecks = []tlsCheck{
	{
		tool: "curl",
		re:   regexp.MustCompile(`\bcurl\b.*\s(?:-k|--insecure)\b`),
		msg:  `curl invoked with "%s" — TLS certificate verification disabled; use --cacert to trust a specific CA instead`,
	},
	{
		tool: "wget",
		re:   regexp.MustCompile(`\bwget\b.*--no-check-certificate\b`),
		msg:  `wget invoked with "--no-check-certificate" — TLS certificate verification disabled; add the CA certificate to the system trust store instead`,
	},
	{
		tool: "git",
		re:   regexp.MustCompile(`\bgit\b.*-c\s+http\.sslVerify\s*=\s*false\b`),
		msg:  `git invoked with "http.sslVerify=false" — TLS certificate verification disabled; configure the CA with http.sslCAInfo instead`,
	},
	{
		tool: "npm",
		re:   regexp.MustCompile(`\bnpm\b.*--strict-ssl\s*=?\s*false\b`),
		msg:  `npm invoked with "--strict-ssl=false" — TLS certificate verification disabled; use cafile in .npmrc to trust a specific CA instead`,
	},
	{
		tool: "npm config",
		re:   regexp.MustCompile(`\bnpm\s+(?:config\s+set|set)\s+strict-ssl\s+false\b`),
		msg:  `npm strict-ssl disabled via "npm config set" — TLS certificate verification disabled for all subsequent npm commands`,
	},
}

// gitSSLNoVerifyRe matches GIT_SSL_NO_VERIFY=true/1 as a variable export or inline env.
var gitSSLNoVerifyRe = regexp.MustCompile(`\bGIT_SSL_NO_VERIFY\s*=\s*(?:true|1)\b`)

func (r *gl042) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	// Check GIT_SSL_NO_VERIFY in top-level variables block
	if vars := parser.FindKey(mapping, "variables"); vars != nil {
		findings = append(findings, checkGitSSLNoVerifyVars(vars, file, "")...)
	}

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkTLSLines(node, file, "")...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkTLSLines(node, file, "")...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if vars := parser.FindKey(job, "variables"); vars != nil {
			findings = append(findings, checkGitSSLNoVerifyVars(vars, file, name.Value)...)
		}
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				findings = append(findings, checkTLSLines(node, file, name.Value)...)
			}
		}
	})

	return findings
}

func checkTLSLines(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		for _, check := range tlsChecks {
			m := check.re.FindString(item.Value)
			if m == "" {
				continue
			}
			msg := check.msg
			if check.tool == "curl" {
				flag := regexp.MustCompile(`-k|--insecure`).FindString(m)
				msg = fmt.Sprintf(msg, flag)
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL042",
				Severity: finding.Warn,
				Job:      job,
				Message:  msg,
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
			break
		}

		if gitSSLNoVerifyRe.MatchString(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL042",
				Severity: finding.Warn,
				Job:      job,
				Message:  `GIT_SSL_NO_VERIFY=true in script — TLS certificate verification disabled for all git operations in this step`,
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}

func checkGitSSLNoVerifyVars(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		if key.Value == "GIT_SSL_NO_VERIFY" && (val.Value == "true" || val.Value == "1") {
			findings = append(findings, finding.Finding{
				RuleID:   "GL042",
				Severity: finding.Warn,
				Job:      job,
				Message:  `GIT_SSL_NO_VERIFY set to "true" in variables — TLS certificate verification disabled for all git operations in affected jobs`,
				File:     file,
				Line:     key.Line,
				Col:      key.Column,
			})
		}
	}
	return findings
}
