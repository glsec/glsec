package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl040 struct{}

var GL040 = &gl040{}

func (r *gl040) ID() string { return "GL040" }

// ftpURLRe matches ftp:// (case-insensitive) but not ftps:// or sftp://.
// \bftp:// won't match sftp:// (no word boundary before ftp in sftp)
// and won't match ftps:// because ftps != ftp followed by ://.
var ftpURLRe = regexp.MustCompile(`(?i)\bftp://`)

// sslReqdRe matches curl's --ssl-reqd flag which upgrades ftp:// to explicit TLS.
var sslReqdRe = regexp.MustCompile(`--ssl-reqd`)

func (r *gl040) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkFTPPlain(node, file, job)...)
	})
	return findings
}

func checkFTPPlain(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if !ftpURLRe.MatchString(item.Value) {
			continue
		}
		// curl --ssl-reqd with ftp:// uses explicit TLS — not plain FTP.
		if sslReqdRe.MatchString(item.Value) {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL040",
			Severity: finding.Warn,
			Job:      job,
			Message:  "script uses plain ftp:// — credentials and content are transmitted unencrypted; use ftps://, sftp://, or curl with --ssl-reqd instead",
			File:     file,
			Line:     item.Line,
			Col:      item.Column,
		})
	}
	return findings
}
