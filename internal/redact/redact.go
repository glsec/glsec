// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Package redact masks secret values in text glsec writes out (#831): finding
// messages in every format and the source lines of the text output. A report
// travels further than the repository: into CI job logs, artifacts, code
// scanning and bug reports.
package redact

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/rules"
)

// tokens are GL006's token formats; masked as a whole, keeping their prefix.
var tokens = rules.TokenPatterns()

// valueAfter are the places a credential follows a fixed prefix. Group 1 is
// the prefix, group 2 the value to mask. A value starting with $ is a
// variable reference and stays.
var valueAfter = []*regexp.Regexp{
	// scheme://user:password@host
	regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^\s/:@"']+:)([^\s/@"'$][^\s/@"']*)@`),
	// Authorization: Bearer|Basic|Token <value>
	regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token)\s+)([^\s"'$][^\s"']*)`),
	// PRIVATE-TOKEN: / JOB-TOKEN: / DEPLOY-TOKEN: headers
	regexp.MustCompile(`(?i)((?:private|job|deploy)-token:\s*)([^\s"'$][^\s"']*)`),
	// curl -u user:password, --user user:password; only for curl, since
	// docker run -u 1000:1000 is a user and group
	regexp.MustCompile(`(\bcurl\b[^\n]*?\s(?:-u|--user)(?:\s+|=)["']?[^\s"':]*:)([^\s"'$][^\s"']*)`),
	// --password value, --password=value (not --password-stdin)
	regexp.MustCompile(`((?:^|\s)--password(?:\s+|=)["']?)([^\s"'$-][^\s"']*)`),
	// NAME=value and NAME: value for a secret-like name, in a script line
	// or a variables: entry
	regexp.MustCompile(`(?i)(\b[A-Z0-9_]*(?:_TOKEN|_SECRET|_PASSWORD|_PASSWD|_PASS|_PWD|_KEY|_CREDENTIAL)\s*(?:=|:\s+)["']?)([^\s"'$][^\s"']*)`),
}

// String returns s with every secret value it recognises masked. The masked
// text has the same length, so columns in a source line stay where they were,
// and it is stable: masking it again changes nothing.
func String(s string) string {
	for _, re := range tokens {
		s = re.ReplaceAllStringFunc(s, mask)
	}
	for _, re := range valueAfter {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			sub := re.FindStringSubmatchIndex(m)
			return m[:sub[4]] + mask(m[sub[4]:sub[5]]) + m[sub[5]:]
		})
	}
	return s
}

// Findings returns a copy of fs with the messages masked.
func Findings(fs []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, len(fs))
	for i, f := range fs {
		f.Message = String(f.Message)
		out[i] = f
	}
	return out
}

// mask keeps a token's prefix, up to its first _ or - within the first 12
// characters (ghp_, glpat-, sk-ant-), and replaces the rest with *. A value
// without such a prefix is masked whole.
func mask(v string) string {
	keep := 0
	if i := strings.IndexAny(v, "_-"); i >= 0 && i < 12 && i+1 < len(v)/2 {
		keep = i + 1
	}
	return v[:keep] + strings.Repeat("*", len([]rune(v[keep:])))
}
