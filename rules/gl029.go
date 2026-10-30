// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl029 struct{}

var GL029 = &gl029{}

func (r *gl029) ID() string { return "GL029" }

// dockerLoginPasswordRe matches "docker login" with the short -p flag (not --password-stdin).
var dockerLoginPasswordRe = regexp.MustCompile(`\b(?:docker|podman)\s+login\b[^;&|\n]*\s(?:-p|--password)(?:\s|=)`)

func (r *gl029) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkDockerLoginPassword(node, file, job)...)
	})
	return findings
}

func checkDockerLoginPassword(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if loc := dockerLoginPasswordRe.FindStringIndex(item.Value); loc != nil {
			tool := "docker"
			if strings.HasPrefix(item.Value[loc[0]:], "podman") {
				tool = "podman" // name the command as written (#1005)
			}
			line, col := scriptMatchPos(item, loc[0])
			findings = append(findings, finding.Finding{
				RuleID:   "GL029",
				Severity: finding.Warn,
				Job:      job,
				Message:  fmt.Sprintf("%s login passes the password with -p or --password — it is visible in the process table; use --password-stdin instead: echo \"$PASSWORD\" | %s login --password-stdin", tool, tool),
				File:     file,
				Line:     line,
				Col:      col,
			})
		}
	}
	return findings
}
