// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl047 struct{}

var GL047 = &gl047{}

func (r *gl047) ID() string { return "GL047" }

// sshRootRe matches an ssh invocation with root as the login user.
// It allows arbitrary flags between ssh and root@ to cover common forms like
// ssh -i key root@host, ssh -p 2222 root@host, ssh -o ... root@host.
var sshRootRe = regexp.MustCompile(`\bssh\b.*\broot@`)

// rootHostRe captures the host after root@.
var rootHostRe = regexp.MustCompile(`\broot@(\[[^\]]+\]|[^\s:/"']+)`)

// onlyLoopbackRoot reports whether every root@ login in line goes to the
// local machine, such as a VM the job started with a forwarded port
// (ssh -p 10022 root@127.0.0.1).
func onlyLoopbackRoot(line string) bool {
	hosts := rootHostRe.FindAllStringSubmatch(line, -1)
	for _, h := range hosts {
		if !isLoopback(strings.Trim(h[1], "[]")) {
			return false
		}
	}
	return len(hosts) > 0
}

func (r *gl047) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		if sshRootRe.MatchString(line.Value) && !onlyLoopbackRoot(line.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL047",
				Severity: finding.Warn,
				Job:      job,
				Message:  "SSH connection as root — use a dedicated least-privilege service account instead of root to limit blast radius if the pipeline is compromised",
				File:     file,
				Line:     line.Line,
				Col:      line.Column,
			})
		}
	})
	return findings
}
