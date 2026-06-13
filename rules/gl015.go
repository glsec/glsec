package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl015 struct{}

var GL015 = &gl015{}

func (r *gl015) ID() string { return "GL015" }

var (
	// dockerCmdRe matches docker or podman build/push/tag/buildx commands.
	dockerCmdRe = regexp.MustCompile(`\b(?:docker|podman)\s+(?:build|push|tag|buildx)\b`)

	// userControlledTagRe matches an image tag that uses a user-controlled variable,
	// i.e. a colon (tag separator) followed by a user-controlled predefined variable.
	// CI_COMMIT_SHA, CI_PIPELINE_ID, and CI_COMMIT_SHORT_SHA are safe — not listed here.
	userControlledTagRe = regexp.MustCompile(
		`:\$\{?(?:CI_COMMIT_REF_NAME|CI_COMMIT_REF_SLUG|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?`,
	)
)

func (r *gl015) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		for _, f := range checkScriptDockerTags(node, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})
	return findings
}

func checkScriptDockerTags(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if dockerCmdRe.MatchString(item.Value) && userControlledTagRe.MatchString(item.Value) {
			m := userControlledTagRe.FindString(item.Value)
			varName := m[2:] // strip ":$"
			if len(varName) > 0 && varName[0] == '{' {
				varName = varName[1 : len(varName)-1] // strip braces
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL015",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"Docker image tag uses user-controlled variable $%s — a branch named \"latest\" or \"main\" overwrites the production tag; use $CI_COMMIT_SHA instead",
					varName,
				),
				File: file,
				Line: item.Line,
				Col:  item.Column,
			})
		}
	}
	return findings
}
